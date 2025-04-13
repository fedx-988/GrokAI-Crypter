# FedX EEXE Crypter

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

## Author

**fedx988**  
- Telegram: @fedx988

## License

This project is released under [The Unlicense](https://unlicense.org/).