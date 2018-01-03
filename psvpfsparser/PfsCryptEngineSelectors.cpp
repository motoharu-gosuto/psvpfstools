#include "PfsCryptEngineSelectors.h"

#include <cstdint>
#include <string>
#include <cstring>

#include "PfsCryptEngineBase.h"

//this macro unwraps 64 bit sector number into byte array
#define UINT64_TO_BYTEARRAY(x, y)                                              \
   { (y)[7] = (unsigned char)((x) >> 56); (y)[6] = (unsigned char)((x) >> 48); \
     (y)[5] = (unsigned char)((x) >> 40); (y)[4] = (unsigned char)((x) >> 32); \
     (y)[3] = (unsigned char)((x) >> 24); (y)[2] = (unsigned char)((x) >> 16); \
     (y)[1] = (unsigned char)((x) >> 8) ; (y)[0] = (unsigned char)(x); }

//this function increments byte array of size 0x10
int UINT128_BYTEARRAY_INC(unsigned char iv[0x10])
{
   for(int i = 0; i < 0x10; i++)
   {
      if(iv[i] == 0xFF)
      {
         iv[i] = 0;
      }
      else
      {
         iv[i] = iv[i] + 1;
         break;
      }
   }

   return 0;
}

//############## LEVEL 2 - CRYPTO WRAPPER SELECTORS ###############

//#### GROUP 1, GROUP 2 (hw dec/enc) ####

unsigned char g_1771100[0x10] = {0};

int pfs_decrypt_hw(const unsigned char* key, const unsigned char* iv_xor_key, std::uint64_t tweak_key, std::uint32_t size, std::uint32_t block_size, const unsigned char* src, unsigned char* dst, std::uint16_t flag, std::uint16_t key_id)
{
   unsigned char iv[0x10] = {0};

   UINT64_TO_BYTEARRAY(tweak_key, iv);

   memset(iv + 8, 0, 8);

   for(int i = 0; i < 0x10; i++)
      iv[i] = iv[i] ^ iv_xor_key[i];
  
   if(size != 0)
   {
      std::uint32_t offset = 0;
      std::uint32_t bytes_left = size;

      do
      {
         std::uint64_t tweak_key_ofst = tweak_key + offset;
         UINT64_TO_BYTEARRAY(tweak_key_ofst, iv);

         memset(iv + 8, 0, 8);

         for(int i = 0; i < 0x10; i++)
            iv[i] = iv[i] ^ iv_xor_key[i];

         // select block_size if we did not yet reach tail of the data. 
         // or select bytes_left which will be the size of the tail in the end

         int size_arg = 0;
         if(block_size < bytes_left)
            size_arg = block_size;
         else
            size_arg = bytes_left;

         if((flag & PFS_CRYPTO_USE_KEYGEN) != 0)
         {
            if((flag & PFS_CRYPTO_USE_CMAC) != 0)
               AESCMACWithKeygen_base_2(key, iv, size_arg, src + offset, g_1771100, key_id);
            else
               AESCBCDecryptWithKeygen_base(key, iv, size_arg, src + offset, dst + offset, key_id);
         }
         else
         {
            if((flag & PFS_CRYPTO_USE_CMAC) != 0)
               AESCMAC_base_1(key, iv, size_arg, src + offset, g_1771100);
            else
               AESCBCDecrypt_base(key, iv, size_arg, src + offset, dst + offset);
         }

         offset = offset + block_size;
         bytes_left = bytes_left - block_size;
      }
      while(size > offset);
   }

   if((flag & PFS_CRYPTO_USE_CMAC) != 0)
   {
      if(dst != src)
      {
         memcpy(dst, src, size);
      }
   }

   return 0;
}

int pfs_encrypt_hw(const unsigned char* key, const unsigned char* iv_xor_key, std::uint64_t tweak_key, std::uint32_t size, std::uint32_t block_size, const unsigned char* src, unsigned char* dst, std::uint16_t flag, std::uint16_t key_id)
{
   unsigned char iv[0x10] = {0};

   UINT64_TO_BYTEARRAY(tweak_key, iv);

   memset(iv + 8, 0, 8);

   for(int i = 0; i < 0x10; i++)
      iv[i] = iv[i] ^ iv_xor_key[i];

   if(size != 0)
   {
      std::uint32_t offset = 0;
      std::uint32_t bytes_left = size;

      do
      {         
         std::uint64_t tweak_key_ofst = tweak_key + offset;
         UINT64_TO_BYTEARRAY(tweak_key_ofst, iv);

         memset(iv + 8, 0, 8);

         for(int i = 0; i < 0x10; i++)
            iv[i] = iv[i] ^ iv_xor_key[i];

         // select block_size if we did not yet reach tail of the data. 
         // or select bytes_left which will be the size of the tail in the end

         int size_arg = 0;
         if(block_size < bytes_left)
            size_arg = block_size;
         else
            size_arg = bytes_left;

         if((flag & PFS_CRYPTO_USE_KEYGEN) != 0)
         {
            if((flag & PFS_CRYPTO_USE_CMAC) != 0)
               AESCMACWithKeygen_base_1(key, iv, size_arg, src + offset, g_1771100, key_id);
            else
               AESCBCEncryptWithKeygen_base(key, iv, size_arg, src + offset, dst + offset, key_id);
         }
         else
         {
            if((flag & PFS_CRYPTO_USE_CMAC) != 0)
               AESCMAC_base_2(key, iv, size_arg, src + offset, g_1771100);
            else
               AESCBCEncrypt_base(key, iv, size_arg, src + offset, dst + offset);
         }

         offset = offset + block_size;
         bytes_left = bytes_left - block_size;
      }
      while(size > offset);
   }

   if((flag & PFS_CRYPTO_USE_CMAC) != 0)
   {
      if(dst != src)
      {
         memcpy(dst, src, size);
      }
   }

   return 0;
}

//#### GROUP 3, GROUP 4 (sw dec/enc) ####

//looks like this method can decrypt multiple blocks when size > block_size
//assuming that it adds 1 to tweak_key when decrypting each next block
//in practice though it looks like this method is only used to decrypt single block

int pfs_decrypt_sw(const unsigned char* key, const unsigned char* subkey_key, std::uint32_t keysize, std::uint64_t tweak_key, std::uint32_t size, std::uint32_t block_size, const unsigned char* src, unsigned char* dst, std::uint16_t flag)
{
   unsigned char iv[0x10] = {0};

   if((block_size <= 0xF) || (size <= 0xF)) //block_size and size should be at least one block
      return 0x80140609;

   UINT64_TO_BYTEARRAY(tweak_key, iv);

   memset(iv + 8, 0, 8);

   std::uint32_t offset = 0;
   std::uint32_t bytes_left = size;

   do
   {
      // select block_size if we did not yet reach tail of the data. 
      // or select bytes_left which will be the size of the tail in the end

      int size_arg = 0;
      if(block_size < bytes_left)
         size_arg = block_size;
      else
         size_arg = bytes_left;

      int result0 = 0;
      if((flag & PFS_CRYPTO_USE_CMAC) != 0)
         result0 = AESCMACSw_base_2(iv, key, subkey_key, keysize, size_arg, src + offset, g_1771100);
      else
         result0 = AESCMACDecryptSw_base(iv, key, subkey_key, keysize, size_arg, src + offset, dst + offset);

      if(result0 != 0)
         return result0;

      UINT128_BYTEARRAY_INC(iv);

      offset = offset + block_size;
      bytes_left = bytes_left - block_size;
   }
   while(size > offset);

   if((flag & PFS_CRYPTO_USE_CMAC) != 0)
   {
      if(dst != src)
      {
         memcpy(dst, src, size);
      }
   }

   return 0;
}

//looks like this method can encrypt multiple blocks when size > block_size
//assuming that it adds 1 to tweak_key when encrypting each next block
//in practice though it looks like this method is only used to decrypt single block

int pfs_encrypt_sw(const unsigned char* key, const unsigned char* subkey_key, std::uint32_t keysize, std::uint64_t tweak_key, std::uint32_t size, std::uint32_t block_size, const unsigned char* src, unsigned char* dst, std::uint16_t flag)
{
   unsigned char iv[0x10] = {0};

   if((block_size <= 0xF) || (size <= 0xF)) //block_size and size should be at least one block
      return 0x80140609;

   UINT64_TO_BYTEARRAY(tweak_key, iv);

   memset(iv + 8, 0, 8);
   
   std::uint32_t offset = 0;
   std::uint32_t bytes_left = size;
   
   do
   {
      // select block_size if we did not yet reach tail of the data. 
      // or select bytes_left which will be the size of the tail in the end

      int size_arg = 0;
      if(block_size < bytes_left)
         size_arg = block_size;
      else
         size_arg = bytes_left;

      int result0 = 0;
      if((flag & PFS_CRYPTO_USE_CMAC) != 0)
         result0 = AESCMACSw_base_1(iv, key, subkey_key, keysize, size_arg, src + offset, g_1771100);
      else
         result0 = AESCMACEncryptSw_base(iv, key, subkey_key, keysize, size_arg, src + offset, dst + offset);
      
      if(result0 != 0)
         return result0;

      UINT128_BYTEARRAY_INC(iv);

      offset = offset + block_size;
      bytes_left = bytes_left - block_size;
   }
   while(size > offset);

   if((flag & PFS_CRYPTO_USE_CMAC) != 0)
   {
      if(dst != src)
      {
         memcpy(dst, src, size);
      }
   }

   return 0;
}