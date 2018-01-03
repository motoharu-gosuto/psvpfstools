#pragma once

#include <cstdint>
#include <libcrypto/aes.h>

int SceKernelUtilsForDriver_sceSha1DigestForDriver(const unsigned char *source, std::uint32_t size, unsigned char result[0x14]);

int SceKernelUtilsForDriver_sceHmacSha1DigestForDriver(const unsigned char* key, std::uint32_t key_len, const unsigned char* data, std::uint32_t data_len, unsigned char digest[0x14]);