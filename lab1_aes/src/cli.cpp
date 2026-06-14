#include "cli.hpp"

#include <iostream>
#include <stdexcept>

static bool starts_with_dash(const std::string& s) {
    return s.rfind("--", 0) == 0;
}

std::map<std::string, std::string> parse_options(int argc, char* argv[], int start_index) {
    std::map<std::string, std::string> opts;

    for (int i = start_index; i < argc; ++i) {
        std::string token = argv[i];

        if (!starts_with_dash(token)) {
            throw std::runtime_error("Unexpected positional argument: " + token);
        }

        std::string key = token.substr(2);
        std::string value = "true";

        if ((i + 1) < argc && !starts_with_dash(argv[i + 1])) {
            value = argv[++i];
        }

        opts[key] = value;
    }

    return opts;
}

std::string require_option(
    const std::map<std::string, std::string>& opts,
    const std::string& name
) {
    auto it = opts.find(name);

    if (it == opts.end() || it->second.empty()) {
        throw std::runtime_error("Missing required option: --" + name);
    }

    return it->second;
}

void print_usage() {
    std::cout
        << "aestool - Lab 1 AES tool using Crypto++\n\n"
        << "Commands:\n"
        << "  keygen  --bits 128|192|256 --out key.bin\n"
        << "  kat     --kat vectors/aes_kat_sample.json\n"
        << "  encrypt --mode ecb|cbc|cfb|ofb|ctr|xts|gcm|ccm --key key.bin --in msg.bin --out ct.bin\n"
        << "  encrypt --mode gcm --aead --key key.bin --text \"message\" --out ct.bin [--aad-text \"aad\"]\n"
        << "  decrypt --mode ecb|cbc|cfb|ofb|ctr|xts|gcm|ccm --key key.bin --in ct.bin --out pt.bin\n\n"
        << "  bench   --out bench_windows.csv [--runs 30] [--ops 1000] [--sizes 1k,4k,16k,256k,1m,8m]\n"
        << "Options:\n"
        << "  --key FILE                 Raw AES key file, length must be 16, 24, or 32 bytes\n"
        << "  --key-hex HEX              AES key in hex format\n"
        << "  --kat FILE                 Run JSON Known Answer Tests\n"
        << "  --iv FILE                  Raw 16-byte IV/tweak file for CBC/CFB/OFB/CTR/XTS\n"
        << "  --iv-hex HEX               16-byte IV/tweak in hex format for CBC/CFB/OFB/CTR/XTS\n"
        << "  --nonce FILE               Raw 12-byte nonce file for GCM\n"
        << "  --nonce-hex HEX            12-byte nonce in hex format for GCM\n"
        << "  --aad FILE                 AAD file for GCM\n"
        << "  --aad-text TEXT            AAD text for GCM\n"
        << "  --allow-ecb                Allow ECB for files larger than 16 KiB in lab testing\n"
        << "  --nonce-registry FILE      Registry file for CTR/GCM nonce reuse detection\n"
        << "  --meta FILE                Metadata JSON sidecar path\n"
        << "  --encode hex|base64|raw    Console encoding for ciphertext/key display\n\n"
        << "  --runs N                  Benchmark repeated runs, default 30\n"
        << "  --ops N                   Operations per timed run, default 1000\n"
        << "  --warmup-ms N             Warm-up time per case, default 1000\n"
        << "  --sizes LIST              Payload sizes, e.g. 1k,4k,16k,256k,1m,8m\n"
        << "  --modes LIST              Modes, e.g. cbc,ctr,gcm,ccm,xts\n"
        << "  --platform TEXT           Platform label for CSV, default windows-mingw64\n"
        << "  --summary FILE            Summary CSV output path\n"
        << "Current milestone supports ECB, CBC, CFB, OFB, CTR, XTS, GCM, and CCM.\n";
}