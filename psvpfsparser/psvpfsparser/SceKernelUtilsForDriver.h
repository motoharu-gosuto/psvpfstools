#pragma once

#include <stdint.h>

int SceKernelUtilsForDriver_aes_init_2(void *ctx, uint32_t blocksize, uint32_t keysize, const unsigned char *key);

int SceKernelUtilsForDriver_aes_encrypt_2(void* ctx, const unsigned char* src, unsigned char* dst);

int SceKernelUtilsForDriver_sceSha1DigestForDriver(const unsigned char *source, uint32_t size, unsigned char result[0x14]);

int SceKernelUtilsForDriver_sceHmacSha1DigestForDriver(const unsigned char* key, uint32_t key_len, const unsigned char* data, uint32_t data_len, unsigned char digest[0x14]);