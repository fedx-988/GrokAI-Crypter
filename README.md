# FedX EXE Crypter

A sophisticated executable crypting tool that encrypts and embeds PE files into PowerShell scripts with advanced obfuscation and persistence capabilities.

## Features

- 🔒 AES-256 encryption with random keys
- 📦 Base64 encoding of encrypted payload
- 🦠 PowerShell script generation with randomized variable names and comments
- 🏃‍♂️ Batch file wrapper with fake ZIP header and massive colon padding
- 🥷 Hidden CMD Window (Windows 10 only) (I think it works)
- 🔄 Startup persistence with cleanup of competing scripts
- 🛡️ Execution policy bypass techniques
- 🕰️ Random file timestamps for evasion
- 🔄 Split string obfuscation for payload and key

## Detection

✅ **[Current detection rate: 0/61](https://www.virustotal.com/gui/file/7e9d4e33d9639e1740da25471352aed1f86efa9aeb4f3f54555d2bf5da56abcf?nocache=1)**  
*Last scanned: 2025/04/18*

## How It Works

1. Takes an input executable file
2. Generates a random 256-bit AES key
3. Encrypts the executable using:
   - AES-256 in CBC mode with PKCS7 padding
   - Random 16-byte IV prepended to ciphertext
4. Embeds the encrypted payload in a PowerShell script that:
   - Reassembles split Base64-encoded payload and key
   - Decrypts the payload in memory
   - Loads and executes the assembly as a .NET assembly
5. Creates a batch file wrapper that:
   - Includes a fake ZIP header and massive colon padding (~150,000 colons)
   - Base64-encodes the PowerShell script with a random marker
   - Executes the script with execution policy bypass
   - Copies itself to the Windows Startup folder

## Usage

1. Make sure to change the C++ Language Standard to C++ 20 ‼️⚠️
2. Compile the C++ program (requires Windows and `bcrypt.lib`)
3. Run the executable
4. Enter the path to the target PE file when prompted
5. The tool will generate:
   - `fedx.ps1` - The obfuscated PowerShell loader script
   - `fedx.bat` - The batch file wrapper with embedded payload

## Technical Details

### Encryption Process
- Random 256-bit AES key generated using Windows Cryptography API (BCrypt)
- AES-256 encryption in CBC mode with PKCS7 padding
- Random 16-byte IV generated for each encryption
- IV prepended to ciphertext for decryption

### Obfuscation Techniques
- Random variable names for PowerShell script
- Random comments inserted in PowerShell script
- Split Base64 payload and key into 3–6 random parts
- Fake ZIP header (`PK\x03\x04`) in batch file
- Massive colon padding (~150,000 colons) in batch file
- Random batch file marker for Base64 payload
- Random delay in batch file execution
- Random file timestamps (1–30 days in the past)

### Persistence
- Copies batch file to Windows Startup folder
- Deletes competing preset batch files in Startup folder
- Handles restricted PowerShell execution policies by relaunching with bypass

## Warning

⚠️ This tool is for educational purposes only.  
⚠️ Use only on systems you own or have permission to test.  
⚠️ The persistence mechanism and obfuscation may be flagged by security software.  
⚠️ The CMD/PowerShell window will remain open on Windows 11 due to a bug in the terminal.

## Credits

💖 Thank you KingKDot for the [Powershell to BAT code](https://github.com/KingKDot/powershell2bat).  
💖 Can't forget [Grok](https://grok.com) itself.

## Author

**fedx988**  
- Telegram: @fedx988

## License

This project is released under The Unlicense.
