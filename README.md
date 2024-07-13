## usmbreak

Command-line tool to encrypt and decrypt CRIWARE USM files. Encoding it is left
as an exercise for the reader.

**HCA audio is not handled by this program. Please encrypt your HCA audio before
muxing the USM.**

Usage:

```
usmbreak <enc | dec> <input> <output> <key>
```

### Credits

Encryption/decryption routines were referenced from [donmai-me](https://github.com/donmai-me)'s
[WannaCRI](https://github.com/donmai-me/WannaCRI) library for handling CRIWARE media formats.
