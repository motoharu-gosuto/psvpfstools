#pragma once

#include <cstdint>
#include <libcrypto/aes.h>

int SceKernelUtilsForDriver_sceSha1DigestForDriver(const unsigned char *source, int size, unsigned char result[0x14]);

int SceKernelUtilsForDriver_sceHmacSha1DigestForDriver(const unsigned char* key, int key_len, const unsigned char* data, int data_len, unsigned char digest[0x14]);