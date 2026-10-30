/*
 * libcrypto_mock.cpp — Stripped Shared Library Target (libcrypto_mock.so)
 * Built with: clang++ -std=c++17 -g -O0 -fno-inline -fno-omit-frame-pointer -fPIC -shared
 * Stripped with: strip -x libcrypto_mock.so
 * Demonstrates Tier-3 Stripped Binary Offset Symbolication (libcrypto_mock.so+0x<offset>)
 * and ELF/Mach-O objdump disassembly extraction.
 */

#include <cstddef>
#include <cstdint>
#include <cstring>

static __attribute__((noinline)) int verify_hmac_signature_internal(const char *token, size_t len) {
    volatile uint64_t acc = 0xCBF29CE484222325ULL;
    for (size_t round = 0; round < 2048; ++round) {
        for (size_t i = 0; i < len; ++i) {
            acc ^= static_cast<uint64_t>(static_cast<unsigned char>(token[i]));
            acc *= 0x100000001B3ULL;
            acc = (acc << 13) | (acc >> 51);
        }
    }
    return (acc != 0) ? 1 : 0;
}

extern "C" __attribute__((noinline)) int verify_request_token(const char *token) {
    if (token == nullptr) {
        return 0;
    }
    size_t len = std::strlen(token);
    if (len == 0) {
        return 0;
    }
    return verify_hmac_signature_internal(token, len);
}
