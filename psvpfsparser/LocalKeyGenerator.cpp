#include "LocalKeyGenerator.h"

#include <cstdint>

#include <fstream>
#include <string>
#include <cstring>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <fstream>

#include <libcrypto/sha256.h>
#include <libcrypto/aes.h>

#include "LocalKeys.h"
#include "Utils.h"

//check functions are based on code provided by Proxima

int check_sealedkey(sealedkey_t& sk)
{
   std::uint8_t result[0x20];

   if(std::string((char*)sk.magic, 8) != SEALEDKEY_MAGIC)
   {
      std::cout << "sealedkey: invalid magic" << std::endl;
      return -1;
   }

   if(sk.type_major != SEALEDKEY_EXPECTED_TYPE_MAJOR)
   {
      std::cout << "sealedkey: invalid type_major" << std::endl;
      return -1;
   }
   
   if(sk.type_minor != SEALEDKEY_EXPECTED_TYPE_MINOR)
   {
      std::cout << "sealedkey: invalid type_minor" << std::endl;
      return -1;
   }

   if(!isZeroVector(sk.padding, sk.padding + sizeof(sk.padding)))
   {
      std::cout << "sealedkey: invalid padding" << std::endl;
      return -1;
   }

   hmac_sha256(sealedkey_retail_key, 0x10, (unsigned char*)&sk, 0x30, result);
   if(memcmp(sk.hmac, result, 0x20) == 0) 
   {
      std::cout << "sealedkey: matched retail hmac" << std::endl;
      return 0;
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
   std::uint8_t result[0x20];

   if(std::string((char*)ks.magic, 8) != KEYSTONE_MAGIC)
   {
      std::cout << "keystone: invalid magic" << std::endl;
      return -1;
   }

   if(ks.type != KEYSTONE_EXPECTED_TYPE)
   {
      std::cout << "keystone: invalid type" << std::endl;
      return -1;
   }
   
   if(ks.version != KEYSTONE_EXPECTED_VERSION)
   {
      std::cout << "keystone: invalid version" << std::endl;
      return -1;
   }

   if(!isZeroVector(ks.padding, ks.padding + sizeof(ks.padding)))
   {
      std::cout << "keystone: invalid padding" << std::endl;
      return -1;
   }

   hmac_sha256(keystone_hmac_secret, 0x20, (unsigned char*)&ks, 0x40, result);
   if(memcmp(ks.keystone_hmac, result, 0x20) == 0) 
   {
      std::cout << "keystone: matched retail hmac" << std::endl;
      return 0;
   } 
   else 
   {
      hmac_sha256(keystone_debug_key, 0x20, (unsigned char*)&ks, 0x40, result);
      if(memcmp(ks.keystone_hmac, result, 0x20) == 0) 
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

int check_keystone(keystone_t& ks, unsigned char* passcode)
{
   if(check_keystone(ks) < 0)
      return -1;

   std::uint8_t result[0x20];

   hmac_sha256(passcode_hmac_secret, 0x20, passcode, 0x20, result);
   if(memcmp(ks.passcode_hmac, result, 0x20) == 0) 
   {
      std::cout << "keystone: matched passcode hmac" << std::endl;
      return 0;
   } 
   else 
   {
      hmac_sha256(passcode_debug_key, 0x20, passcode, 0x20, result);
      if(memcmp(ks.passcode_hmac, result, 0x20) == 0) 
      {
         std::cout << "keystone: matched debug passcode hmac!" << std::endl;
         return 0;
      }
      else
      {
         std::cout << "keystone: failed to match passcode hmac" << std::endl;
         return -1;
      }
   }
}

//public functions

int get_sealedkey(boost::filesystem::path titleIdPath, unsigned char* dec_key)
{
   boost::filesystem::path root(titleIdPath);
   boost::filesystem::path filepath = root / "sce_sys" / "sealedkey";

   if(!boost::filesystem::exists(filepath))
   {
      std::cout << "sealedkey does not exist" << std::endl;
      return -1;
   }

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

int get_keystone(boost::filesystem::path titleIdPath, char* passcode)
{
   boost::filesystem::path root(titleIdPath);
   boost::filesystem::path filepath = root / "sce_sys" / "keystone";

   if(!boost::filesystem::exists(filepath))
   {
      std::cout << "keystone does not exist" << std::endl;
      return -1;
   }

   keystone_t ks;

   std::ifstream inputStream(filepath.generic_string().c_str(), std::ios::in | std::ios::binary);
   inputStream.read((char*)&ks, 0x60);

   if(passcode == 0)
      return check_keystone(ks);
   else
      return check_keystone(ks, (unsigned char*)passcode);

   return 0;
}
