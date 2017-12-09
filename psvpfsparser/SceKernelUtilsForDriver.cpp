#include "SceKernelUtilsForDriver.h"

#include <libcrypto/sha1.h>

//##### SW CRYPTO FUNCTIONS #####

int SceKernelUtilsForDriver_aes_init_2(void *ctx, std::uint32_t blocksize, std::uint32_t keysize, const unsigned char *key)
{
   return 0;
}

int SceKernelUtilsForDriver_aes_encrypt_2(void* ctx, const unsigned char* src, unsigned char* dst)
{
   return 0;
}

//##### SW HASH FUNCTIONS #####

int SceKernelUtilsForDriver_sceSha1DigestForDriver(const unsigned char *source, std::uint32_t size, unsigned char result[0x14])
{
   sha1(source, size, result);
   return 0;
}

int SceKernelUtilsForDriver_sceHmacSha1DigestForDriver(const unsigned char* key, std::uint32_t key_len, const unsigned char* data, std::uint32_t data_len, unsigned char digest[0x14])
{
   sha1_hmac(key, key_len, data, data_len, digest);
   return 0;
}