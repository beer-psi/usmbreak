use std::{
    fmt::Display,
    fs::{self, File},
    io::{BufReader, BufWriter, Read, Write},
    path::PathBuf,
    process,
};

use anyhow::Result;
use clap::{Parser, Subcommand};
use dialoguer::Confirm;
use indicatif::{ProgressBar, ProgressStyle};

fn main() -> Result<()> {
    let cli = Cli::parse();

    let opts = match cli.command {
        Commands::Encrypt { ref opts } => opts,
        Commands::Decrypt { ref opts } => opts,
    };

    if opts.key >= 72057594037927936 {
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

    let mut video_key = [0u8; 0x40];
    let mut audio_key = [0u8; 0x20];

    generate_keys(opts.key, &mut video_key, &mut audio_key)?;

    let video_key = video_key;
    let audio_key = audio_key;
    let mut rolling = [0u8; 0x40];

    let fin = File::open(&opts.input)?;
    let filesize = fin.metadata()?.len();
    let mut reader = BufReader::with_capacity(65535, fin);

    if let Some(parent) = opts.output.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)?;
        }
    }

    let fout = File::create(&opts.output)?;
    
    fout.set_len(filesize)?;
    
    let mut writer = BufWriter::with_capacity(65535, fout);
    let mut buffer: Vec<u8> = Vec::with_capacity(65535);
    let mut packet_meta = [0u8; 16];
    let pb = ProgressBar::new(filesize)
        .with_style(
            ProgressStyle::default_bar()
                .template("{prefix} [{bar:20!.bright.yellow/dim.white}] {bytes:>8} [{elapsed}<{eta}, {bytes_per_sec}]")?
        );

    match cli.command {
        Commands::Encrypt { .. } => pb.set_prefix("Encrypting"),
        Commands::Decrypt { .. } => pb.set_prefix("Decrypting"),
    };

    while reader.read_exact(&mut packet_meta).is_ok() {
        writer.write_all(&packet_meta)?;
        pb.inc(packet_meta.len() as u64);

        let packet_type = std::str::from_utf8(&packet_meta[..4])?;
        let size = u32::from_be_bytes(packet_meta[4..8].try_into()?) as usize;
        let payload_offset = packet_meta[9];
        let padding_size = u16::from_be_bytes(packet_meta[10..12].try_into()?);
        let payload_type = packet_meta[15];

        let is_audio_packet = packet_type == "@SFA";
        let is_video_packet = packet_type == "@SFV";

        // Skip and write directly to output if
        // - not a stream payload (payload_type 0)
        // - not an audio/video packet
        if payload_type != 0 || (!is_audio_packet && !is_video_packet) {
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

        if is_video_packet {
            rolling[..].copy_from_slice(&video_key);

            if let Commands::Encrypt { .. } = cli.command {
                encrypt_video_packet(&mut buffer, &video_key, &mut rolling)?;
            } else {
                decrypt_video_packet(&mut buffer, &video_key, &mut rolling)?;
            }

            writer.write_all(&buffer[..payload_size])?;
        } else if is_audio_packet {
            crypt_audio_packet(&mut buffer, &audio_key)?;
            writer.write_all(&buffer[..payload_size])?;
        } else {
            panic!("Another packet type got through the filter? {packet_type}");
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

/// Program to encrypt/decrypt USMs
#[derive(Parser, Debug)]
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

// URUC in bytes.
const AUDIO_T: [u8; 4] = [0x55, 0x52, 0x55, 0x43];

fn generate_keys(
    cipher_key: u64,
    video_key: &mut [u8],
    audio_key: &mut [u8],
) -> Result<(), UsmBreakError> {
    if video_key.len() < 0x40 || audio_key.len() < 0x20 {
        return Err(UsmBreakError::BufferTooShort);
    }

    let cipher_key = cipher_key.to_le_bytes();
    let mut key = [0u8; 0x20];

    key[0x00] = cipher_key[0];
    key[0x01] = cipher_key[1];
    key[0x02] = cipher_key[2];
    key[0x03] = cipher_key[3].wrapping_sub(0x34);
    key[0x04] = cipher_key[4].wrapping_add(0xF9);
    key[0x05] = cipher_key[5] ^ 0x13;
    key[0x06] = cipher_key[6].wrapping_add(0x61);
    key[0x07] = key[0x00] ^ 0xFF;
    key[0x08] = key[0x01].wrapping_add(key[0x02]);
    key[0x09] = key[0x01].wrapping_sub(key[0x07]);
    key[0x0A] = key[0x02] ^ 0xFF;
    key[0x0B] = key[0x01] ^ 0xFF;
    key[0x0C] = key[0x0B].wrapping_add(key[0x09]);
    key[0x0D] = key[0x08].wrapping_sub(key[0x03]);
    key[0x0E] = key[0x0D] ^ 0xFF;
    key[0x0F] = key[0x0A].wrapping_sub(key[0x0B]);
    key[0x10] = key[0x08].wrapping_sub(key[0x0F]);
    key[0x11] = key[0x10] ^ key[0x07];
    key[0x12] = key[0x0F] ^ 0xFF;
    key[0x13] = key[0x03] ^ 0x10;
    key[0x14] = key[0x04].wrapping_sub(0x32);
    key[0x15] = key[0x05].wrapping_add(0xED);
    key[0x16] = key[0x06] ^ 0xF3;
    key[0x17] = key[0x13].wrapping_sub(key[0x0F]);
    key[0x18] = key[0x15].wrapping_add(key[0x07]);
    key[0x19] = (0x21u8).wrapping_sub(key[0x13]);
    key[0x1A] = key[0x14] ^ key[0x17];
    key[0x1B] = key[0x16].wrapping_add(key[0x16]);
    key[0x1C] = key[0x17].wrapping_add(0x44);
    key[0x1D] = key[0x03].wrapping_add(key[0x04]);
    key[0x1E] = key[0x05].wrapping_sub(key[0x16]);
    key[0x1F] = key[0x1D] ^ key[0x13];

    for i in 0..0x20 {
        video_key[i] = key[i];
        video_key[0x20 + i] = key[i] ^ 0xFF;
        audio_key[i] = if i % 2 != 0 {
            AUDIO_T[(i >> 1) % 4]
        } else {
            key[i] ^ 0xFF
        };
    }

    Ok(())
}

fn decrypt_video_packet(
    packet: &mut [u8],
    video_key: &[u8],
    rolling: &mut [u8],
) -> Result<(), UsmBreakError> {
    if video_key.len() < 0x40 || rolling.len() < 0x40 {
        return Err(UsmBreakError::KeyTooShort);
    }

    let encrypted_part_size = packet.len() - 0x40;

    if encrypted_part_size < 0x200 {
        return Ok(());
    }

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
    if video_key.len() < 0x40 || rolling.len() < 0x40 {
        return Err(UsmBreakError::KeyTooShort);
    }

    let encrypted_part_size = packet.len() - 0x40;

    if encrypted_part_size < 0x200 {
        return Ok(());
    }

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
    if audio_key.len() < 0x20 {
        return Err(UsmBreakError::KeyTooShort);
    }

    let packet_length = packet.len();

    if packet_length <= 0x140 {
        return Ok(());
    }

    for i in 0x140..packet_length {
        packet[i] ^= audio_key[i % 0x20];
    }

    Ok(())
}
