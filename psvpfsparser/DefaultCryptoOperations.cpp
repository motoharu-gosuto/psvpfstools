#include "DefaultCryptoOperations.h"

#include <libcrypto/aes.h>
#include <libcrypto/sha1.h>
#include <libcrypto/sha256.h>

int DefaultCryptoOperations::aes_cbc_encrypt(const unsigned char* src, unsigned char* dst, int size, const unsigned char* key, int key_size, unsigned char* iv) const
{
   aes_context aes_ctx;
   memset(&aes_ctx, 0, sizeof(aes_ctx));
   aes_setkey_enc(&aes_ctx, key, key_size);
   int res = aes_crypt_cbc(&aes_ctx, AES_ENCRYPT, size, iv, src, dst);
   return res == 0 ? 0 : -1;
}

int DefaultCryptoOperations::aes_cbc_decrypt(const unsigned char* src, unsigned char* dst, int size, const unsigned char* key, int key_size, unsigned char* iv) const  
{
   aes_context aes_ctx;
   memset(&aes_ctx, 0, sizeof(aes_ctx));
   aes_setkey_dec(&aes_ctx, key, key_size);
   int res = aes_crypt_cbc(&aes_ctx, AES_DECRYPT, size, iv, src, dst);
   return res == 0 ? 0 : -1;
}

int DefaultCryptoOperations::aes_ecb_encrypt(const unsigned char* src, unsigned char* dst, int size, const unsigned char* key, int key_size) const  
{
   int nBlocks = size / 0x10;
   int tailSize = size % 0x10;

   if(tailSize > 0)
      return -1; //Data has to be padded in aes ecb

   aes_context aes_ctx;
   memset(&aes_ctx, 0, sizeof(aes_ctx));
   aes_setkey_enc(&aes_ctx, key, key_size);

   for(int i = 0; i < nBlocks; i++)
   {
      int res = aes_crypt_ecb(&aes_ctx, AES_ENCRYPT, src + i * 0x10, dst + i * 0x10);
      if(res != 0)
         return -1;
   }

   return 0;
}

int DefaultCryptoOperations::aes_ecb_decrypt(const unsigned char* src, unsigned char* dst, int size, const unsigned char* key, int key_size) const
{
   int nBlocks = size / 0x10;
   int tailSize = size % 0x10;

   if(tailSize > 0)
      return -1; //Data has to be padded in aes ecb

   aes_context aes_ctx;
   memset(&aes_ctx, 0, sizeof(aes_ctx));
   aes_setkey_dec(&aes_ctx, key, key_size);

   for(int i = 0; i < nBlocks; i++)
   {
      int res = aes_crypt_ecb(&aes_ctx, AES_DECRYPT, src + i * 0x10, dst + i * 0x10);
      if(res != 0)
         return -1;
   }

   return 0;
}
   
int DefaultCryptoOperations::aes_cmac(const unsigned char* src, unsigned char* dst, int size, const unsigned char* key, int key_size) const
{
   aes_context aes_ctx;
   memset(&aes_ctx, 0, sizeof(aes_ctx));
   aes_setkey_enc(&aes_ctx, key, key_size);

   ::aes_cmac(&aes_ctx, size, src, dst);
   return 0;
}
   
int DefaultCryptoOperations::sha1(const unsigned char* src, unsigned char* dst, int size) const
{
   ::sha1(src, size, dst);
   return 0;
}

int DefaultCryptoOperations::hmac_sha1(const unsigned char* src, unsigned char* dst, int size, const unsigned char* key, int key_size) const
{
   ::sha1_hmac(key, key_size, src, size, dst);
   return 0;
}

int DefaultCryptoOperations::hmac_sha256(const unsigned char* src, unsigned char* dst, int size, const unsigned char* key, int key_size) const
{
   return ::hmac_sha256(key, key_size, src, size, dst);
}