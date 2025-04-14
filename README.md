# FedX EXE Crypter

A sophisticated executable crypting tool that encrypts and embeds PE files into PowerShell scripts with persistence capabilities.

![GitHub](https://img.shields.io/badge/license-Unlicense-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey.svg)

## Features

- 🔒 XOR-based encryption with key derivation
- 🔄 Byte shuffling for added obfuscation
- 📦 Base64 encoding of payload
- 🦠 PowerShell script generation with random variable obfuscation
- 🏃‍♂️ Batch file wrapper with massive colon padding
- 🔄 Startup persistence mechanism
- 🛡️ Execution policy bypass techniques

## Detection

✅ **Current detection rate: 0/61**  
VirusTotal Scan: [View Results](https://www.virustotal.com/gui/file/a3d1736c2cf2d80ebc92afe288ff69734c9d70bf2a2d0b5575dccb096c8ebd78/detection)

*Last scanned: 2025-04-13*

## How It Works

1. Takes an input executable file
2. Generates a random encryption key
3. Encrypts the executable using:
   - Dual-layer XOR encryption
   - Byte shuffling based on key values
4. Embeds the encrypted payload in a PowerShell script that:
   - Derives decryption keys
   - Reverses the encryption process
   - Loads and executes the assembly in memory
5. Creates a batch file wrapper that:
   - Contains massive colon padding for obfuscation
   - Base64-encodes the PowerShell script
   - Handles execution policy restrictions
   - Copies itself to Windows Startup folder

## Usage

1. Compile the C++ program
2. Run the executable
3. Enter path to the target PE file when prompted
4. The tool will generate:
   - `fedx.ps1` - The PowerShell loader script
   - `fedx.bat` - The obfuscated batch file wrapper

## Technical Details

### Encryption Process
- Key generation using cryptographically-strong random characters
- Key derivation function with multiple rounds
- Two-phase XOR encryption with intermediate shuffling

### Obfuscation Techniques
- Random variable name generation
- Massive colon padding in batch file
- Base64 encoding of PowerShell script
- Execution policy bypass mechanisms

### Persistence
- Automatic copy to Windows Startup folder (.BAT Only)
- Special handling for restricted execution policies

## Warning

⚠️ This tool is for educational purposes only.  
⚠️ Use only on systems you own or have permission to test.  
⚠️ The persistence mechanism may be flagged by security software.  
⚠️ The CMD/Powershell window will stay open on Windows 11 due to a bug in the Windows terminal.

## Credits

Thank you [KingKDot](https://github.com/KingKDot) for the [Powershell to BAT code](https://github.com/KingKDot/powershell2bat).
Can't forget [Grok](https://grok.com) itself.

## Author

**fedx988**  
- Telegram: @fedx988



## License

This project is released under [The Unlicense](https://unlicense.org/).
