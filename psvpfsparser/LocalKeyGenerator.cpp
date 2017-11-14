#include "LocalKeyGenerator.h"

#include <stdint.h>

#include <string>
#include <cstring>
#include <iostream>
#include <stdexcept>

#include <libcrypto/sha256.h>
#include <libcrypto/aes.h>

#include "LocalKeys.h"

//two check functions are based on code provided by Proxima

int check_sealedkey(sealedkey_t& sk)
{
   uint8_t result[0x20];

   hmac_sha256(sealedkey_retail_key, 0x10, (unsigned char*)&sk, 0x30, result);
   if(memcmp(sk.hmac, result, 0x20) == 0) 
   {
      std::cout << "sealedkey: matched retail hmac" << std::endl;
      return 1;
   } 
   else 
   {
      hmac_sha256(sealedkey_debug_key, 0x10, (unsigned char*)&sk, 0x30, result);
      if(memcmp(sk.hmac, result, 0x20) == 0) 
      {
         std::cout << "sealedkey: matched debug hmac" << std::endl;
         return 0;
      } 
      else 
      {
         std::cout << "sealedkey: failed to match hmac" << std::endl;
         return -1;
      }
   }
}

int check_keystone(keystone_t& ks)
{
   uint8_t result[0x20];

   hmac_sha256(keystone_hmac_secret1, 0x20, (unsigned char*)&ks, 0x40, result);
   if(memcmp(ks.hmac, result, 0x20) == 0) 
   {
      std::cout << "keystone: matched retail hmac" << std::endl;
      return 0;
   } 
   else 
   {
      hmac_sha256(keystone_hmac_secret2, 0x20, (unsigned char*)&ks, 0x40, result);
      if(memcmp(ks.hmac, result, 0x20) == 0) 
      {
         std::cout << "keystone: matched retail hmac" << std::endl;
         return 0;
      } 
      else 
      {
         hmac_sha256(keystone_debugkey, 0x20, (unsigned char*)&ks, 0x40, result);
         if(memcmp(ks.hmac, result, 0x20) == 0) 
         {
            std::cout << "keystone: matched debug hmac!" << std::endl;
            return 0;
         }
         else
         {
            std::cout << "keystone: failed to match hmac" << std::endl;
            return -1;
         }
      }
   }
}

//public functions

int get_sealedkey(boost::filesystem::path titleIdPath, unsigned char* dec_key)
{
   boost::filesystem::path root(titleIdPath);
   boost::filesystem::path filepath = root / "sce_sys" / "sealedkey";

   sealedkey_t sk;

   std::ifstream inputStream(filepath.generic_string().c_str(), std::ios::in | std::ios::binary);
   inputStream.read((char*)&sk, sizeof(sealedkey_t));

   if(check_sealedkey(sk) < 0)
      return -1;

   aes_context aes_ctx;
   memset(&aes_ctx, 0, sizeof(aes_ctx));
   aes_setkey_dec(&aes_ctx, PFS_EncKey, 128);
   aes_crypt_cbc(&aes_ctx, AES_DECRYPT, sizeof(sk.enc_key), sk.iv, sk.enc_key, dec_key);

   return 0;
}

int get_keystone(boost::filesystem::path titleIdPath, unsigned char* dec_key)
{
   boost::filesystem::path root(titleIdPath);
   boost::filesystem::path filepath = root / "sce_sys" / "keystone";

   keystone_t ks;

   std::ifstream inputStream(filepath.generic_string().c_str(), std::ios::in | std::ios::binary);
   inputStream.read((char*)&ks, 0x60);

   if(check_keystone(ks) < 0)
      return -1;

   /*
   aes_context aes_ctx;
   memset(&aes_ctx, 0, sizeof(aes_ctx));
   aes_setkey_dec(&aes_ctx, ?, 128);
   aes_crypt_cbc(&aes_ctx, AES_DECRYPT, sizeof(ks.enc_key), ks.iv, ks.enc_key, dec_key);
   */

   throw std::runtime_error("get_keystone key decryption is not implemented");

   return 0;
}