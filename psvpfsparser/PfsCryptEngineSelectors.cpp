#include "PfsCryptEngineSelectors.h"

#include <cstdint>
#include <string>
#include <cstring>

#include "PfsCryptEngineBase.h"

//############## LEVEL 2 - CRYPTO WRAPPER SELECTORS ###############

//#### GROUP 1, GROUP 2 (hw dec/enc) ####

unsigned char g_1771100[0x10] = {0};

int pfs_decrypt_hw(const unsigned char* key, const unsigned char* iv_xor_key, int tweak_key0, int tweak_key1, std::uint32_t size, std::uint32_t block_size, const unsigned char* src, unsigned char* dst, std::uint16_t flag, std::uint16_t key_id)
{
   unsigned char iv[0x10] = {0};

   //this piece of code unwraps 64 bit sector number into byte array
   //like here https://github.com/libtom/libtomcrypt/blob/c14bcf4d302f954979f0de43f7544cf30873f5a6/src/headers/tomcrypt_macros.h#L23

   int tk_tmp00 = tweak_key0; //sector_number_hi
   int tk_tmp10 = tweak_key1; //sector_number_lo
   
   for(int i = 0; i < 8; i++)
   {
      iv[i] = tk_tmp00;

      tk_tmp00 = (tk_tmp00 >> 8) | (tk_tmp10 << 24);
      tk_tmp10 = tk_tmp10 >> 8;
   }

   memset(iv + 8, 0, 8);

   for(int i = 0; i < 0x10; i++)
      iv[i] = iv[i] ^ iv_xor_key[i];
  
   if(size != 0)
   {
      std::uint32_t offset = 0;
      std::uint32_t bytes_left = size;

      do
      {
         int tk_tmp01 = tweak_key0 + offset;
         int tk_tmp11 = tweak_key1 + 0;
         
         for(int i = 0; i < 8; i++)
         {
            iv[i] = tk_tmp01;
            
            tk_tmp01 = (tk_tmp01 >> 8) | (tk_tmp11 << 24);
            tk_tmp11 = tk_tmp11 >> 8;
         }

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

int pfs_encrypt_hw(const unsigned char* key, const unsigned char* iv_xor_key, int tweak_key0, int tweak_key1, std::uint32_t size, std::uint32_t block_size, const unsigned char* src, unsigned char* dst, std::uint16_t flag, std::uint16_t key_id)
{
   unsigned char iv[0x10] = {0};

   int tk_tmp00 = tweak_key0;
   int tk_tmp10 = tweak_key1;

   for(int i = 0; i < 8; i++)
   {
      iv[i] = tk_tmp00;

      tk_tmp00 = (tk_tmp00 >> 8) | (tk_tmp10 << 24);
      tk_tmp10 = tk_tmp10 >> 8;
   }

   memset(iv + 8, 0, 8);

   for(int i = 0; i < 0x10; i++)
      iv[i] = iv[i] ^ iv_xor_key[i];

   if(size != 0)
   {
      std::uint32_t offset = 0;
      std::uint32_t bytes_left = size;

      do
      {         
         int tk_tmp01 = tweak_key0 + offset;
         int tk_tmp11 = tweak_key1 + 0;

         for(int i = 0; i < 8; i++)
         {
            iv[i] = tk_tmp01;

            tk_tmp01 = (tk_tmp01 >> 8) | (tk_tmp11 << 24);
            tk_tmp11 = tk_tmp11 >> 8;
         }

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

int pfs_decrypt_sw(const unsigned char* key, const unsigned char* subkey_key, std::uint32_t keysize, int tweak_key0, int tweak_key1, std::uint32_t size, std::uint32_t block_size, const unsigned char* src, unsigned char* dst, std::uint16_t flag)
{
   unsigned char iv[0x10] = {0};

   if(((block_size | size) << 0x1C) != 0)
      return 0x80140609;

   if(size <= 0xF)
      return 0x80140609;
 
   /*
   if((((int)src | (int)dst) << 0x1E) != 0)
      return 0x8014060E;
   */

   int tk_tmp00 = tweak_key0;
   int tk_tmp10 = tweak_key1;

   for(int i = 0; i < 8; i++)
   {
      iv[i] = tk_tmp00;

      tk_tmp00 = (tk_tmp00 >> 8) | (tk_tmp10 << 24);
      tk_tmp10 = tk_tmp10 >> 8;
   }

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

int pfs_encrypt_sw(const unsigned char* key, const unsigned char* subkey_key, std::uint32_t keysize, int tweak_key0, int tweak_key1, std::uint32_t size, std::uint32_t block_size, const unsigned char* src, unsigned char* dst, std::uint16_t flag)
{
   unsigned char iv[0x10] = {0};

   if(((block_size | size) << 0x1C) != 0)
      return 0x80140609;

   if(size <= 0xF)
      return 0x80140609;

   /*
   if((((int)src | (int)dst) << 0x1E) != 0)
      return 0x8014060E;
   */

   int tk_tmp00 = tweak_key0;
   int tk_tmp10 = tweak_key1;

   for(int i = 0; i < 8; i++)
   {
      iv[i] = tk_tmp00;

      tk_tmp00 = (tk_tmp00 >> 8) | (tk_tmp10 << 24);
      tk_tmp10 = tk_tmp10 >> 8;
   }

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