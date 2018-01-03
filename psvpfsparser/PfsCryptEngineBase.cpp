#include "PfsCryptEngineBase.h"

#include <cstdint>
#include <string>
#include <cstring>

#include "SceSblSsMgrForDriver.h"
#include "SceKernelUtilsForDriver.h"

//############## CRYPTO BASE WRAPPERS ###############

//#### GROUP 1 (hw dec/enc) ####

//encrypt / decrypt

//ok
int AESCBCEncrypt_base(const unsigned char* key, unsigned char* iv, std::uint32_t size, const unsigned char* src, unsigned char* dst)
{
   int size_tail = size & 0xF;
   int size_block = size & (~0xF);

   //encrypt N blocks of source data with key and iv
   
   if(size_block != 0)
   {
      int result0 = SceSblSsMgrForDriver_sceSblSsMgrAESCBCEncryptForDriver(src, dst, size_block, key, 0x80, iv, 1);
      if(result0 != 0)
         return result0;
   }

   //handle tail section - do a Cipher Text Stealing

   if(size_tail == 0)
      return 0;

   //align destination buffer

   unsigned char iv_enc[0x10] = {0};

   //encrypt iv using key

   int result1 = SceSblSsMgrForDriver_sceSblSsMgrAESECBEncryptForDriver(iv, iv_enc, 0x10, key, 0x80, 1);
   if(result1 != 0)
      return result1;

   for(int i = 0; i < size_tail; i++)
      dst[size_block + i] = src[size_block + i] ^ iv_enc[i]; 

   return 0;
}

//ok
int AESCBCDecrypt_base(const unsigned char* key, unsigned char* iv, std::uint32_t size, const unsigned char* src, unsigned char* dst)
{
   int size_tail = size & 0xF; // get size of tail
   int size_block = size & (~0xF); // get block size aligned to 0x10 boundary

   //decrypt N blocks of source data with key and iv

   if(size_block != 0)
   {
      int result0 = SceSblSsMgrForDriver_sceSblSsMgrAESCBCDecryptForDriver(src, dst, size_block, key, 0x80, iv, 1);
      if(result0 != 0)
         return result0;
   }

   //handle tail section - do a Cipher Text Stealing

   if(size_tail == 0)
      return 0;

   //align destination buffer

   unsigned char iv_enc[0x10] = {0};
   
   //encrypt iv using key

   int result1 = SceSblSsMgrForDriver_sceSblSsMgrAESECBEncryptForDriver(iv, iv_enc, 0x10, key, 0x80, 1);
   if(result1 != 0)
      return result1;

   //produce destination tail by xoring source tail with encrypted iv

   for(int i = 0; i < size_tail; i++)
      dst[size_block + i] = src[size_block + i] ^ iv_enc[i];

   return 0;
}

//encrypt / decrypt with key_id

//ok
int AESCBCDecryptWithKeygen_base(const unsigned char* key, unsigned char* iv, std::uint32_t size, const unsigned char* src, unsigned char* dst, std::uint16_t key_id)
{
   std::uint16_t kid = 0 - (key_id - 1) + (key_id - 1);

   int size_tail = size & 0xF;
   int size_block = size & (~0xF);
   
   //decrypt N blocks of source data with key and iv

   if(size_block != 0)
   {
      int result0 = SceSblSsMgrForDriver_sceSblSsMgrAESCBCDecryptWithKeygenForDriver(src, dst, size_block, key, 0x80, iv, kid, 1);
      if(result0 != 0)
         return result0;
   }

   //handle tail section - do a Cipher Text Stealing

   if(size_tail == 0)
      return 0;

   //align destination buffer

   unsigned char iv_enc[0x10] = {0};

   //encrypt iv using key

   int result1 = SceSblSsMgrForDriver_sceSblSsMgrAESECBEncryptWithKeygenForDriver(iv, iv_enc, 0x10, key, 0x80, kid, 1);
   if(result1 != 0)
      return result1;

   //produce destination tail by xoring source tail with encrypted iv

   for(int i = 0; i < size_tail; i++)
      dst[size_block + i] = src[size_block + i] ^ iv_enc[i];

   return 0;
}

//ok
int AESCBCEncryptWithKeygen_base(const unsigned char* klicensee, unsigned char* iv, std::uint32_t size, const unsigned char* src, unsigned char* dst, std::uint16_t key_id)
{
   std::uint16_t kid = 0 - (key_id - 1) + (key_id - 1); // ???

   int size_tail = size & 0xF; // get size of tail
   int size_block = size & (~0xF); // get block size aligned to 0x10 boundary
   
   //encrypt N blocks of source data with klicensee and iv

   if(size_block != 0)
   {
      int result0 = SceSblSsMgrForDriver_sceSblSsMgrAESCBCEncryptWithKeygenForDriver(src, dst, size_block, klicensee, 0x80, iv, kid, 1);
      if(result0 != 0)
         return result0;  
   }

   //handle tail section - do a Cipher Text Stealing

   if(size_tail == 0)
      return 0;

   //align destination buffer

   unsigned char iv_enc[0x10] = {0};

   //encrypt iv using klicensee
     
   int result1 = SceSblSsMgrForDriver_sceSblSsMgrAESECBEncryptWithKeygenForDriver(iv, iv_enc, 0x10, klicensee, 0x80, kid, 1);
   if(result1 != 0)
      return result1;

   //produce destination tail by xoring source tail with encrypted iv

   for(int i = 0; i < size_tail; i++)
      dst[size_block + i] = src[size_block + i] ^ iv_enc[i];

   return 0;
}

//#### GROUP 2 (hw cmac) ####

// FUNCTIONS ARE SIMILAR

int AESCMAC_base_1(const unsigned char* cmac_key, unsigned char* iv, std::uint32_t size, const unsigned char* cmac_src, unsigned char* cmac_dst)
{
   throw std::runtime_error("Untested unknown behavior");

   int size_tail = size & 0xF;
   int size_block = size & (~0xF);
   
   //cmac N blocks of source data with klicensee and iv

   if(size_block != 0)
   {
      int result0 = SceSblSsMgrForDriver_sceSblSsMgrAESCMACForDriver(cmac_src, cmac_dst, size_block, cmac_key, 0x80, iv, 1, 0);
      if(result0 != 0)
         return result0;
   }

   //handle tail section - do a Cipher Text Stealing

   if(size_tail == 0)
      return 0;

   //align destination buffer

   unsigned char iv_enc[0x10] = {0};

   //encrypt iv using key

   int result1 = SceSblSsMgrForDriver_sceSblSsMgrAESECBEncryptForDriver(iv, iv_enc, 0x10, cmac_key, 0x80, 1);
   if(result1 != 0)
      return result1;

   //produce destination tail by xoring source tail with encrypted iv

   //CMAC result has constant size - that is why iv is xored with the beginning of dest buffer

   for(int i = 0; i < size_tail; i++)
      cmac_dst[i] = cmac_src[size_block + i] ^ iv_enc[i];

   return 0;
}

int AESCMAC_base_2(const unsigned char* cmac_key, unsigned char* iv, std::uint32_t size, const unsigned char* cmac_src, unsigned char* cmac_dst)
{
   throw std::runtime_error("Untested unknown behavior");

   int size_tail = size & 0xF;
   int size_block = size & (~0xF);

   //cmac N blocks of source data with klicensee and iv

   if(size_block != 0)
   {
      int result0 = SceSblSsMgrForDriver_sceSblSsMgrAESCMACForDriver(cmac_src, cmac_dst, size_block, cmac_key, 0x80, iv, 1, 0);
      if(result0 != 0)
         return result0;
   }

   //handle tail section - do a Cipher Text Stealing

   if(size_tail == 0)
      return 0;

   //align destination buffer

   unsigned char iv_enc[0x10] = {0};

   //encrypt iv using key

   int result1 = SceSblSsMgrForDriver_sceSblSsMgrAESECBEncryptForDriver(iv, iv_enc, 0x10, cmac_key, 0x80, 1);
   if(result1 != 0)
      return result1;

   //produce destination tail by xoring source tail with encrypted iv

   //CMAC result has constant size - that is why iv is xored with the beginning of dest buffer

   for(int i = 0; i < size_tail; i++)
      cmac_dst[i] = cmac_src[size_block + i] ^ iv_enc[i];

   return 0;
}

// FUNCTIONS ARE SIMILAR

int AESCMACWithKeygen_base_1(const unsigned char* cmac_key, unsigned char* iv, std::uint32_t size, const unsigned char* cmac_src, unsigned char* cmac_dst, std::uint16_t key_id)
{
   throw std::runtime_error("Untested unknown behavior");

   std::uint16_t kid = 0 - (key_id - 1) + (key_id - 1);

   int size_tail = size & 0xF;
   int size_block = size & (~0xF);

   //cmac N blocks of source data with klicensee and iv

   if(size_block != 0)
   {
      int result0 = SceSblSsMgrForDriver_sceSblSsMgrAESCMACWithKeygenForDriver(cmac_src, cmac_dst, size_block, cmac_key, 0x80, iv, kid, 1, 0);
      if(result0 != 0)
         return result0;
   }

   //handle tail section - do a Cipher Text Stealing
   
   if(size_tail == 0)
      return 0;

   //align destination buffer

   unsigned char iv_enc[0x10] = {0};

   //encrypt iv using key

   int result1 = SceSblSsMgrForDriver_sceSblSsMgrAESECBEncryptWithKeygenForDriver(iv, iv_enc, 0x10, cmac_key, 0x80, kid, 1);
   if(result1 != 0)
      return result1;

   //produce destination tail by xoring source tail with encrypted iv

   //CMAC result has constant size - that is why iv is xored with the beginning of dest buffer

   for(int i = 0; i < size_tail; i++)
      cmac_dst[i] = cmac_src[size_block + i] ^ iv_enc[i];

   return 0;
}

int AESCMACWithKeygen_base_2(const unsigned char* cmac_key, unsigned char* iv, std::uint32_t size, const unsigned char* cmac_src, unsigned char* cmac_dst, std::uint16_t key_id)
{
   throw std::runtime_error("Untested unknown behavior");

   std::uint16_t kid = 0 - (key_id - 1) + (key_id - 1);

   int size_tail = size & 0xF;
   int size_block = size & (~0xF);

   //cmac N blocks of source data with klicensee and iv

   if(size_block != 0)
   {
      int result0 = SceSblSsMgrForDriver_sceSblSsMgrAESCMACWithKeygenForDriver(cmac_src, cmac_dst, size_block, cmac_key, 0x80, iv, kid, 1, 0);
      if(result0 != 0)
         return result0;
   }

   //handle tail section - do a Cipher Text Stealing

   if(size_tail == 0)
      return 0;

   //align destination buffer

   unsigned char iv_enc[0x10] = {0};

   //encrypt iv using key
   
   int result1 = SceSblSsMgrForDriver_sceSblSsMgrAESECBEncryptWithKeygenForDriver(iv, iv_enc, 0x10, cmac_key, 0x80, kid, 1);
   if(result1 != 0)
      return result1;

   //produce destination tail by xoring source tail with encrypted iv

   //CMAC result has constant size - that is why iv is xored with the beginning of dest buffer

   for(int i = 0; i < size_tail; i++)
      cmac_dst[i] = cmac_src[size_block + i] ^ iv_enc[i];

   return 0;
}

//#### GROUP 3 (sw dec/enc) ####

// this is most likely SW version of CMAC. both dec and enc functions are implemented
//https://crypto.stackexchange.com/questions/47223/xex-mode-how-to-perturb-the-tweak

//this is more likely to be related to aes-ctx multiplication
//because in cmac last byte of subkey is xored with 0x87, not first
//CMAC
//https://stackoverflow.com/questions/29163493/aes-cmac-calculation-c-sharp
//XTS-AES
//https://github.com/libtom/libtomcrypt/blob/c14bcf4d302f954979f0de43f7544cf30873f5a6/src/modes/xts/xts_mult_x.c#L31

std::uint32_t adds(std::uint32_t left, std::uint32_t right, std::uint32_t* carry)
{
   std::uint64_t l64 = left;
   std::uint64_t r64 = right;
   std::uint64_t res64 = l64 + r64;

   if((res64 & 0x0000000100000000) > 0)
      *carry = 1;
   else
      *carry = 0;

   return res64;
}

std::uint32_t adcs(std::uint32_t left, std::uint32_t right, std::uint32_t* carry)
{
   std::uint64_t l64 = left;
   std::uint64_t r64 = right;
   std::uint64_t res64 = l64 + r64 + *carry;

   if((res64 & 0x0000000100000000) > 0)
      *carry = 1;
   else
      *carry = 0;

   return res64;
}

int xor_1(std::uint32_t* src, std::uint32_t* iv, std::uint32_t* dst, std::uint32_t size)
{
   std::uint32_t iv_cpy[4] = {0};
   memcpy(iv_cpy, iv, 0x10);

   while(size != 0)
   {
      dst[0] = src[0] ^ iv_cpy[0];
      dst[1] = src[1] ^ iv_cpy[1];
      dst[2] = src[2] ^ iv_cpy[2];
      dst[3] = src[3] ^ iv_cpy[3];

      src += 4;
      dst += 4;
      
      std::uint32_t carry = 0;
      iv_cpy[0] = adds(iv_cpy[0], iv_cpy[0], &carry);
      iv_cpy[1] = adcs(iv_cpy[1], iv_cpy[1], &carry);
      iv_cpy[2] = adcs(iv_cpy[2], iv_cpy[2], &carry);
      iv_cpy[3] = adcs(iv_cpy[3], iv_cpy[3], &carry);

      if(carry > 0)
         iv_cpy[0] = iv_cpy[0] ^ 0x87;
      
      size = size - 0x10;
   }

   return 0;
}

//IV is a subkey base

//ok
int AESCMACDecryptSw_base(const unsigned char* subkey, const unsigned char* dst_key, const unsigned char* subkey_key, std::uint32_t key_size, std::uint32_t size, const unsigned char* src, unsigned char* dst)
{
   aes_context aes_ctx;
   unsigned char drv_subkey[0x10] = {0};

   SceKernelUtilsForDriver_aes_init_2(&aes_ctx, 0x80, key_size, subkey_key); //initialize aes ctx with iv_key

   SceKernelUtilsForDriver_aes_encrypt_2(&aes_ctx, subkey, drv_subkey); //encrypt 0x10 bytes of subkey to derive drv_subkey

   xor_1((std::uint32_t*)src, (std::uint32_t*)drv_subkey, (std::uint32_t*)dst, size); // xor src with drv_iv to get dst

   int result0 = SceSblSsMgrForDriver_sceSblSsMgrAESECBDecryptForDriver(dst, dst, size, dst_key, key_size, 1); //decrypt dst data using dst_key key
   if(result0 == 0)
      xor_1((std::uint32_t*)dst, (std::uint32_t*)drv_subkey, (std::uint32_t*)dst, size); //xor dst with drv_iv to get real dst

   return result0;
}

//ok
int AESCMACEncryptSw_base(const unsigned char* subkey, const unsigned char* dst_key, const unsigned char* subkey_key, std::uint32_t key_size, std::uint32_t size, const unsigned char* src, unsigned char* dst)
{
   aes_context aes_ctx;
   unsigned char drv_subkey[0x10] = {0};

   SceKernelUtilsForDriver_aes_init_2(&aes_ctx, 0x80, key_size, subkey_key);

   SceKernelUtilsForDriver_aes_encrypt_2(&aes_ctx, subkey, drv_subkey);

   xor_1((std::uint32_t*)src, (std::uint32_t*)drv_subkey, (std::uint32_t*)dst, size);

   int result0 = SceSblSsMgrForDriver_sceSblSsMgrAESECBEncryptForDriver(dst, dst, size, dst_key, key_size, 1);
   if(result0 == 0)
      xor_1((std::uint32_t*)dst, (std::uint32_t*)drv_subkey, (std::uint32_t*)dst, size);

   return result0;
}

//#### GROUP 4 (sw cmac) ####

// this is some CMAC variation but I am not sure ? both functions are similar but most likely ment to be dec / enc

int xor_2(std::uint32_t* src, std::uint32_t* iv, std::uint32_t* dst, std::uint32_t size)
{
   std::uint32_t iv_cpy[4] = {0};
   memcpy(iv_cpy, iv, 0x10);

   while(size != 0)
   {
      dst[0] = src[0] ^ iv_cpy[0];
      dst[1] = src[1] ^ iv_cpy[1];
      dst[2] = src[2] ^ iv_cpy[2];
      dst[3] = src[3] ^ iv_cpy[3];

      src += 4;
      dst += 4;
      
      std::uint32_t carry = 0;
      iv_cpy[0] = adds(iv_cpy[0], iv_cpy[0], &carry);
      iv_cpy[1] = adcs(iv_cpy[1], iv_cpy[1], &carry);
      iv_cpy[2] = adcs(iv_cpy[2], iv_cpy[2], &carry);
      iv_cpy[3] = adcs(iv_cpy[3], iv_cpy[3], &carry);

      if(carry > 0)
         iv_cpy[0] = iv_cpy[0] ^ 0x87;
      
      size = size - 0x10;
   }

   return 0;
}

int AESCMACSw_base_1(const unsigned char* subkey, const unsigned char* dst_key, const unsigned char* subkey_key, std::uint32_t keysize, std::uint32_t size, const unsigned char* src, unsigned char* dst)
{
   throw std::runtime_error("Untested unknown behavior");

   aes_context aes_ctx;
   unsigned char drv_subkey[0x10] = {0};
   unsigned char iv[0x10] = {0}; //HOW IV IS INITIALIZED ? - it should not be initialized. sceSblSsMgrAESCMACForDriver only takes 0 as IV - look at wiki
   
   SceKernelUtilsForDriver_aes_init_2(&aes_ctx, 0x80, keysize, subkey_key);

   SceKernelUtilsForDriver_aes_encrypt_2(&aes_ctx, subkey, drv_subkey);

   xor_2((std::uint32_t*)src, (std::uint32_t*)drv_subkey, (std::uint32_t*)dst, size); // WHAT DOES THIS DO IF dst IS OVERWRITTEN BY NEXT CMAC CALL ANYWAY ?

   int result0 = SceSblSsMgrForDriver_sceSblSsMgrAESCMACForDriver(src, dst, size, dst_key, keysize, iv, 1, 0);
   if(result0 == 0)
      xor_2((std::uint32_t*)dst, (std::uint32_t*)drv_subkey, (std::uint32_t*)dst, size);

   return result0;
}

int AESCMACSw_base_2(const unsigned char* subkey, const unsigned char* dst_key, const unsigned char* subkey_key, std::uint32_t keysize, std::uint32_t size, const unsigned char* src, unsigned char* dst)
{
   throw std::runtime_error("Untested unknown behavior");

   aes_context aes_ctx;
   unsigned char drv_subkey[0x10] = {0};
   unsigned char iv[0x10] = {0}; //HOW IV IS INITIALIZED ? - it should not be initialized. sceSblSsMgrAESCMACForDriver only takes 0 as IV - look at wiki

   SceKernelUtilsForDriver_aes_init_2(&aes_ctx, 0x80, keysize, subkey_key);

   SceKernelUtilsForDriver_aes_encrypt_2(&aes_ctx, subkey, drv_subkey);

   xor_2((std::uint32_t*)src, (std::uint32_t*)drv_subkey, (std::uint32_t*)dst, size); // WHAT DOES THIS DO IF dst IS OVERWRITTEN BY NEXT CMAC CALL ANYWAY ?

   int result0 = SceSblSsMgrForDriver_sceSblSsMgrAESCMACForDriver(src, dst, size, dst_key, keysize, iv, 1, 0);
   
   if(result0 == 0)
      xor_2((std::uint32_t*)dst, (std::uint32_t*)drv_subkey, (std::uint32_t*)dst, size);

   return result0;
}