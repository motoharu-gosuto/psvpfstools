#pragma once

#include <cstdint>

#define PFS_CRYPTO_USE_CMAC   0x0001 //1
#define PFS_CRYPTO_USE_KEYGEN 0x0002 //2

//#### GROUP 1 (possible keygen aes-cbc-cts dec/aes-cbc-cts enc) ####
//#### GROUP 2 (possible keygen aes-cmac-cts dec/aes-cmac-cts enc) (technically there is no dec/enc - this is pair of same functions since cmac) ####

int pfs_decrypt_hw(const unsigned char* key, const unsigned char* iv_xor_key, std::uint64_t tweak_key, std::uint32_t size, std::uint32_t block_size, const unsigned char* src, unsigned char* dst, std::uint16_t flag, std::uint16_t key_id);

int pfs_encrypt_hw(const unsigned char* key, const unsigned char* iv_xor_key, std::uint64_t tweak_key, std::uint32_t size, std::uint32_t block_size, const unsigned char* src, unsigned char* dst, std::uint16_t flag, std::uint16_t key_id);

//#### GROUP 3 (no keygen xts-aes dec/xts-aes enc) ####
//#### GROUP 4 (no keygen xts-cmac dec/xts-cmac enc) (technically there is no dec/enc - this is pair of same functions since cmac) ####

int pfs_decrypt_sw(const unsigned char* key, const unsigned char* subkey_key, std::uint32_t keysize, std::uint64_t tweak_key, std::uint32_t size, std::uint32_t block_size, const unsigned char* src, unsigned char* dst, std::uint16_t flag);

int pfs_encrypt_sw(const unsigned char* key, const unsigned char* subkey_key, std::uint32_t keysize, std::uint64_t tweak_key, std::uint32_t size, std::uint32_t block_size, const unsigned char* src, unsigned char* dst, std::uint16_t flag);