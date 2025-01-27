use std::{
    ffi::CStr,
    fmt::Display,
    fs::{self, File},
    io::{BufReader, BufWriter, Read, Write},
    path::PathBuf,
    process,
};

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use dialoguer::Confirm;
use indicatif::{ProgressBar, ProgressStyle};

/// Video and audio encryption for USM files uses separate keys, derived from a shared key.
/// The derivation process only uses the lower 56 bits, meaning `0x10EF_1234_5678_ABCD`
/// is equivalent to `0x00EF_1234_5678_ABCD`.
///
/// While it is not forbidden, emit a warning if the user decides to use a key larger than
/// the effective maximum.
const MAX_EFFECTIVE_KEY: u64 = 0x00FF_FFFF_FFFF_FFFF;

/// The size of the derived video key.
const VIDEO_KEY_SIZE: usize = 0x40;

/// The size of the derived audio key.
const AUDIO_KEY_SIZE: usize = 0x20;

/// The minimum size for a video packet to have encrypted content. Any video packets smaller
/// than this size are left unencrypted.
const MIN_VIDEO_ENCRYPT_SIZE: usize = 0x240;

/// The minimum size for an audio packet to have encrypted content. Any audio packets smaller
/// than this size are left unecrypted.
const MIN_AUDIO_ENCRYPT_SIZE: usize = 0x141;

/// The size of an USM packet header. It includes:
/// - Packet type ([FourCC](https://en.wikipedia.org/wiki/FourCC))
/// - Data size (4 bytes, big endian)
/// - Unknown (1 byte)
/// - Offset of packet payload (1 byte)
/// - Size of packet padding (2 bytes, big endian)
/// - Channel number (1 byte)
/// - Unknown 2 bytes
/// - Data type (1 byte)
///   - 0: Stream
///   - 1: Header
///   - 2: Section end
///   - 3: Metadata
const PACKET_HEADER_SIZE: usize = 16;

/// Used for mixing in the audio key on odd-indexed bytes.
const AUDIO_T: [u8; 4] = *b"URUC";

/// Initial size of in-memory buffer for encrypting/decrypting content,
/// and buffer size for the [`std::io::BufReader`]/[`std::io::BufWriter`].
const BUFFER_SIZE: usize = 65535;

const PACKET_TYPE_VIDEO: [u8; 4] = *b"@SFV";
const PACKET_TYPE_AUDIO: [u8; 4] = *b"@SFA";
const PACKET_TYPE_ALPHA: [u8; 4] = *b"@ALP";
const PACKET_TYPE_TABLE: [u8; 4] = *b"@UTF";

const PAYLOAD_TYPE_STREAM: u8 = 0;
const PAYLOAD_TYPE_HEADER: u8 = 1;

const ELEMENT_RECURRENCE_YES: u8 = 1;
const ELEMENT_RECURRENCE_NO: u8 = 2;

const AUDIO_CODEC_HCA: u8 = 4;

const TABLE_ROW_TYPE_I8: u8 = 0x10;
const TABLE_ROW_TYPE_U8: u8 = 0x11;
const TABLE_ROW_TYPE_I16: u8 = 0x12;
const TABLE_ROW_TYPE_U16: u8 = 0x13;
const TABLE_ROW_TYPE_I32: u8 = 0x14;
const TABLE_ROW_TYPE_U32: u8 = 0x15;
const TABLE_ROW_TYPE_I64: u8 = 0x16;
const TABLE_ROW_TYPE_U64: u8 = 0x17;
const TABLE_ROW_TYPE_F32: u8 = 0x18;
const TABLE_ROW_TYPE_F64: u8 = 0x19;
const TABLE_ROW_TYPE_CSTR: u8 = 0x1A;
const TABLE_ROW_TYPE_BYTES: u8 = 0x1B;

fn main() -> Result<()> {
    let cli = Cli::parse();

    let opts = match cli.command {
        Commands::Encrypt { ref opts } => opts,
        Commands::Decrypt { ref opts } => opts,
    };

    if opts.key > MAX_EFFECTIVE_KEY {
        println!("Warning: Only the lower 56 bits of the key will be used.");
    }

    if !opts.input.is_file() {
        println!("Error: Input not found, or is not a file.");
        process::exit(1);
    }

    if opts.output.exists() {
        if !opts.output.is_file() {
            println!("Error: Output exists and is not a file.");
            process::exit(1);
        }

        let confirmation = if !opts.force {
            Confirm::new()
                .with_prompt("Output file exists. Overwrite?")
                .default(false)
                .interact()?
        } else {
            true
        };

        if !confirmation {
            process::exit(1);
        }
    }

    let mut video_key = [0u8; VIDEO_KEY_SIZE];
    let mut audio_key = [0u8; AUDIO_KEY_SIZE];

    generate_keys(opts.key, &mut video_key, &mut audio_key)?;

    let video_key = video_key;
    let audio_key = audio_key;
    let mut rolling = [0u8; VIDEO_KEY_SIZE];

    let fin = File::open(&opts.input)?;
    let filesize = fin.metadata()?.len();
    let mut reader = BufReader::with_capacity(BUFFER_SIZE, fin);

    if let Some(parent) = opts.output.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)?;
        }
    }

    let fout = File::create(&opts.output)?;

    fout.set_len(filesize)?;

    let mut writer = BufWriter::with_capacity(BUFFER_SIZE, fout);
    let mut buffer: Vec<u8> = Vec::with_capacity(BUFFER_SIZE);
    let mut packet_meta = [0u8; PACKET_HEADER_SIZE];
    let pb = ProgressBar::new(filesize)
        .with_style(
            ProgressStyle::default_bar()
                .template("{prefix} [{bar:20!.bright.yellow/dim.white}] {bytes:>8} [{elapsed}<{eta}, {bytes_per_sec}]")?
        );

    match cli.command {
        Commands::Encrypt { .. } => pb.set_prefix("Encrypting"),
        Commands::Decrypt { .. } => pb.set_prefix("Decrypting"),
    };

    let mut hca_do_not_touch = false;

    while reader.read_exact(&mut packet_meta).is_ok() {
        writer.write_all(&packet_meta)?;
        pb.inc(packet_meta.len() as u64);

        let packet_type = &packet_meta[..4];
        let size = u32::from_be_bytes(packet_meta[4..8].try_into()?) as usize;
        let payload_offset = packet_meta[9];
        let padding_size = u16::from_be_bytes(packet_meta[10..12].try_into()?);
        let payload_type = packet_meta[15];

        let is_audio_packet = packet_type == PACKET_TYPE_AUDIO;
        let is_video_packet = packet_type == PACKET_TYPE_VIDEO;
        let is_alpha_packet = packet_type == PACKET_TYPE_ALPHA;

        // Skip and write directly to output if
        // - not a stream payload (payload_type 0)
        // - not an audio/video/alpha packet
        if (payload_type != PAYLOAD_TYPE_STREAM && payload_type != PAYLOAD_TYPE_HEADER)
            || (!is_audio_packet && !is_video_packet && !is_alpha_packet)
        {
            let reference = Read::by_ref(&mut reader);
            let remaining_size = size - 0x08;

            buffer.clear();
            reference
                .take(remaining_size as u64)
                .read_to_end(&mut buffer)
                .expect("Didn't read enough");
            writer.write_all(&buffer[..remaining_size])?;
            pb.inc(remaining_size as u64);
            continue;
        }

        let payload_size = size - payload_offset as usize - padding_size as usize;

        // Copy the header over.
        {
            let reference = Read::by_ref(&mut reader);
            let remaining_header_length = (payload_offset - 0x08) as usize;

            buffer.clear();
            reference
                .take(remaining_header_length as u64)
                .read_to_end(&mut buffer)
                .expect("Didn't read enough");
            writer.write_all(&buffer[..remaining_header_length])?;
            pb.inc(remaining_header_length as u64);
        }

        // Read the packet contents.
        {
            let reference = Read::by_ref(&mut reader);

            buffer.clear();
            reference
                .take(payload_size as u64)
                .read_to_end(&mut buffer)?;
        }

        // Metadata packet. We parse just enough of the AUDIO_HDRINFO table to determine if we're dealing
        // with HCA audio instead of ADX, which is encrypted separately.
        if is_audio_packet && payload_type == PAYLOAD_TYPE_HEADER {
            if buffer[..4] != PACKET_TYPE_TABLE {
                return Err(anyhow!(
                    "Error: Received metadata packet type, but the payload was not a table?"
                ));
            }

            let strings_offset = u32::from_be_bytes(buffer[12..16].try_into()?) as usize;
            let byte_array_offset = u32::from_be_bytes(buffer[16..20].try_into()?) as usize;
            let table_name_offset = u32::from_be_bytes(buffer[20..24].try_into()?) as usize;

            let string_array = &buffer[8 + strings_offset..8 + byte_array_offset];
            let table_name = CStr::from_bytes_until_nul(&string_array[table_name_offset..])?;

            if table_name == c"AUDIO_HDRINFO" {
                let table_data_offset = u32::from_be_bytes(buffer[8..12].try_into()?) as usize;
                let num_columns = u16::from_be_bytes(buffer[24..26].try_into()?) as usize;
                let row_data_size = u16::from_be_bytes(buffer[26..28].try_into()?) as usize;
                let num_rows = u32::from_be_bytes(buffer[28..32].try_into()?) as usize;
                let table_data = &buffer
                    [8 + table_data_offset..8 + table_data_offset + row_data_size * num_rows];
                let column_metadata = &buffer[0x20..8 + table_data_offset];

                if num_rows > 1 {
                    return Err(anyhow!("AUDIO_HDRINFO table has more than one row?!"));
                }

                let mut table_data_offset = 0;

                for i in 0..num_columns {
                    let element_name_offset =
                        u32::from_be_bytes(column_metadata[i * 5 + 1..i * 5 + 5].try_into()?)
                            as usize;
                    let element_name =
                        CStr::from_bytes_until_nul(&string_array[element_name_offset..])?;
                    let element_type = column_metadata[i * 5] & 0x1F;
                    let element_recurrence = column_metadata[i * 5] >> 5;

                    // We can just not care.
                    if element_recurrence == ELEMENT_RECURRENCE_YES {
                        continue;
                    }

                    let element_size = match element_type {
                        TABLE_ROW_TYPE_I8 | TABLE_ROW_TYPE_U8 => 1,
                        TABLE_ROW_TYPE_I16 | TABLE_ROW_TYPE_U16 => 2,
                        TABLE_ROW_TYPE_I32 | TABLE_ROW_TYPE_U32 | TABLE_ROW_TYPE_F32
                        | TABLE_ROW_TYPE_CSTR => 4,
                        TABLE_ROW_TYPE_I64 | TABLE_ROW_TYPE_U64 | TABLE_ROW_TYPE_F64
                        | TABLE_ROW_TYPE_BYTES => 8,
                        _ => return Err(anyhow!("Unknown table element type {element_type:0x}.")),
                    };

                    if element_name != c"audio_codec" {
                        table_data_offset += element_size;
                        continue;
                    }

                    // Non-recurring I8
                    if element_type != TABLE_ROW_TYPE_I8
                        || element_recurrence != ELEMENT_RECURRENCE_NO
                    {
                        return Err(anyhow!(
                            "Invalid AUDIO_HDRINFO table: audio_codec is not a non recurring I8."
                        ));
                    }

                    let encoding = table_data[table_data_offset];

                    hca_do_not_touch = encoding == AUDIO_CODEC_HCA;
                    break;
                }
            }

            writer.write_all(&buffer[..payload_size])?;
        } else if is_video_packet || is_alpha_packet {
            rolling[..].copy_from_slice(&video_key);

            if let Commands::Encrypt { .. } = cli.command {
                encrypt_video_packet(&mut buffer, &video_key, &mut rolling)?;
            } else {
                decrypt_video_packet(&mut buffer, &video_key, &mut rolling)?;
            }

            writer.write_all(&buffer[..payload_size])?;
        } else if is_audio_packet {
            // HCA encryption is done separately.
            if !hca_do_not_touch {
                crypt_audio_packet(&mut buffer, &audio_key)?;
            }
            writer.write_all(&buffer[..payload_size])?;
        } else {
            writer.write_all(&buffer[..payload_size])?;
        }

        pb.inc(payload_size as u64);

        {
            let reference = Read::by_ref(&mut reader);

            buffer.clear();
            reference
                .take(padding_size as u64)
                .read_to_end(&mut buffer)?;
            writer.write_all(&buffer[..padding_size as usize])?;
            pb.inc(padding_size as u64);
        }
    }

    writer.flush()?;

    Ok(())
}

fn valid_enc_key(s: &str) -> Result<u64, String> {
    clap_num::maybe_hex_range(s, 1, u64::MAX)
}

#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Parser, PartialEq, Eq)]
struct CommandOpts {
    input: PathBuf,

    output: PathBuf,

    #[arg(value_parser = valid_enc_key)]
    key: u64,

    #[arg(short, long)]
    force: bool,
}

#[derive(Debug, Subcommand, PartialEq, Eq)]
enum Commands {
    #[command(alias = "enc")]
    Encrypt {
        #[command(flatten)]
        opts: CommandOpts,
    },

    #[command(alias = "dec")]
    Decrypt {
        #[command(flatten)]
        opts: CommandOpts,
    },
}

#[derive(Debug)]
enum UsmBreakError {
    BufferTooShort,
    KeyTooShort,
}

impl std::error::Error for UsmBreakError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }

    fn cause(&self) -> Option<&dyn std::error::Error> {
        self.source()
    }
}

impl Display for UsmBreakError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BufferTooShort => {
                write!(f, "The buffer was too small to hold the video/audio key.")
            }
            Self::KeyTooShort => write!(f, "The video/audio key was too short."),
        }
    }
}

fn generate_keys(
    cipher_key: u64,
    video_key: &mut [u8],
    audio_key: &mut [u8],
) -> Result<(), UsmBreakError> {
    if video_key.len() < VIDEO_KEY_SIZE || audio_key.len() < AUDIO_KEY_SIZE {
        return Err(UsmBreakError::BufferTooShort);
    }

    let cipher_key = cipher_key.to_le_bytes();

    video_key[0x00] = cipher_key[0];
    video_key[0x01] = cipher_key[1];
    video_key[0x02] = cipher_key[2];
    video_key[0x03] = cipher_key[3].wrapping_sub(0x34);
    video_key[0x04] = cipher_key[4].wrapping_add(0xF9);
    video_key[0x05] = cipher_key[5] ^ 0x13;
    video_key[0x06] = cipher_key[6].wrapping_add(0x61);
    video_key[0x07] = video_key[0x00] ^ 0xFF;
    video_key[0x08] = video_key[0x01].wrapping_add(video_key[0x02]);
    video_key[0x09] = video_key[0x01].wrapping_sub(video_key[0x07]);
    video_key[0x0A] = video_key[0x02] ^ 0xFF;
    video_key[0x0B] = video_key[0x01] ^ 0xFF;
    video_key[0x0C] = video_key[0x0B].wrapping_add(video_key[0x09]);
    video_key[0x0D] = video_key[0x08].wrapping_sub(video_key[0x03]);
    video_key[0x0E] = video_key[0x0D] ^ 0xFF;
    video_key[0x0F] = video_key[0x0A].wrapping_sub(video_key[0x0B]);
    video_key[0x10] = video_key[0x08].wrapping_sub(video_key[0x0F]);
    video_key[0x11] = video_key[0x10] ^ video_key[0x07];
    video_key[0x12] = video_key[0x0F] ^ 0xFF;
    video_key[0x13] = video_key[0x03] ^ 0x10;
    video_key[0x14] = video_key[0x04].wrapping_sub(0x32);
    video_key[0x15] = video_key[0x05].wrapping_add(0xED);
    video_key[0x16] = video_key[0x06] ^ 0xF3;
    video_key[0x17] = video_key[0x13].wrapping_sub(video_key[0x0F]);
    video_key[0x18] = video_key[0x15].wrapping_add(video_key[0x07]);
    video_key[0x19] = (0x21u8).wrapping_sub(video_key[0x13]);
    video_key[0x1A] = video_key[0x14] ^ video_key[0x17];
    video_key[0x1B] = video_key[0x16].wrapping_add(video_key[0x16]);
    video_key[0x1C] = video_key[0x17].wrapping_add(0x44);
    video_key[0x1D] = video_key[0x03].wrapping_add(video_key[0x04]);
    video_key[0x1E] = video_key[0x05].wrapping_sub(video_key[0x16]);
    video_key[0x1F] = video_key[0x1D] ^ video_key[0x13];

    for i in 0..0x20 {
        video_key[0x20 + i] = !video_key[i];
        audio_key[i] = if i % 2 != 0 {
            AUDIO_T[(i >> 1) % 4]
        } else {
            !video_key[i]
        };
    }

    Ok(())
}

fn decrypt_video_packet(
    packet: &mut [u8],
    video_key: &[u8],
    rolling: &mut [u8],
) -> Result<(), UsmBreakError> {
    if video_key.len() < VIDEO_KEY_SIZE || rolling.len() < VIDEO_KEY_SIZE {
        return Err(UsmBreakError::KeyTooShort);
    }

    let packet_length = packet.len();

    if packet_length < MIN_VIDEO_ENCRYPT_SIZE {
        return Ok(());
    }

    let encrypted_part_size = packet_length - 0x40;

    for i in 0x100..encrypted_part_size {
        let packet_idx = 0x40 + i;
        let key_idx = 0x20 + i % 0x20;

        packet[packet_idx] ^= rolling[key_idx];
        rolling[key_idx] = packet[packet_idx] ^ video_key[key_idx];
    }

    for i in 0..0x100 {
        let key_idx = i % 0x20;

        rolling[key_idx] ^= packet[0x140 + i];
        packet[0x40 + i] ^= rolling[key_idx];
    }

    Ok(())
}

fn encrypt_video_packet(
    packet: &mut [u8],
    video_key: &[u8],
    rolling: &mut [u8],
) -> Result<(), UsmBreakError> {
    if video_key.len() < VIDEO_KEY_SIZE || rolling.len() < VIDEO_KEY_SIZE {
        return Err(UsmBreakError::KeyTooShort);
    }

    let packet_length = packet.len();

    if packet_length < MIN_VIDEO_ENCRYPT_SIZE {
        return Ok(());
    }

    let encrypted_part_size = packet_length - 0x40;

    for i in 0..0x100 {
        let key_idx = i % 0x20;

        rolling[key_idx] ^= packet[0x140 + i];
        packet[0x40 + i] ^= rolling[key_idx];
    }

    for i in 0x100..encrypted_part_size {
        let packet_idx = 0x40 + i;
        let key_idx = 0x20 + i % 0x20;
        let plain = packet[packet_idx];

        packet[packet_idx] ^= rolling[key_idx];
        rolling[key_idx] = plain ^ video_key[key_idx];
    }

    Ok(())
}

fn crypt_audio_packet(packet: &mut [u8], audio_key: &[u8]) -> Result<(), UsmBreakError> {
    if audio_key.len() < AUDIO_KEY_SIZE {
        return Err(UsmBreakError::KeyTooShort);
    }

    let packet_length = packet.len();

    if packet_length < MIN_AUDIO_ENCRYPT_SIZE {
        return Ok(());
    }

    for i in 0x140..packet_length {
        packet[i] ^= audio_key[i % 0x20];
    }

    Ok(())
}
