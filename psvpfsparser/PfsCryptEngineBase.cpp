#include "PfsCryptEngineBase.h"

#include <cstdint>
#include <string>
#include <cstring>

#include "SceSblSsMgrForDriver.h"
#include "SceKernelUtilsForDriver.h"

//#### FUNCTIONS OF GROUP 1/2 are used to encrypt/decrypt unicv.db ####

//#### GROUP 1 (possible keygen aes-cbc-cts dec/aes-cbc-cts enc) ####

//ok
int AESCBCEncrypt_base(const unsigned char* key, unsigned char* tweak, std::uint32_t size, const unsigned char* src, unsigned char* dst)
{
   int size_tail = size & 0xF;
   int size_block = size & (~0xF);

   //encrypt N blocks of source data with key and iv
   
   if(size_block != 0)
   {
      int result0 = SceSblSsMgrForDriver_sceSblSsMgrAESCBCEncryptForDriver(src, dst, size_block, key, 0x80, tweak, 1);
      if(result0 != 0)
         return result0;
   }

   //handle tail section - do a Cipher Text Stealing

   if(size_tail == 0)
      return 0;

   //align destination buffer

   unsigned char tweak_enc[0x10] = {0};

   //encrypt iv using key

   int result1 = SceSblSsMgrForDriver_sceSblSsMgrAESECBEncryptForDriver(tweak, tweak_enc, 0x10, key, 0x80, 1);
   if(result1 != 0)
      return result1;

   for(int i = 0; i < size_tail; i++)
      dst[size_block + i] = src[size_block + i] ^ tweak_enc[i]; 

   return 0;
}

//ok
int AESCBCDecrypt_base(const unsigned char* key, unsigned char* tweak, std::uint32_t size, const unsigned char* src, unsigned char* dst)
{
   int size_tail = size & 0xF; // get size of tail
   int size_block = size & (~0xF); // get block size aligned to 0x10 boundary

   //decrypt N blocks of source data with key and iv

   if(size_block != 0)
   {
      int result0 = SceSblSsMgrForDriver_sceSblSsMgrAESCBCDecryptForDriver(src, dst, size_block, key, 0x80, tweak, 1);
      if(result0 != 0)
         return result0;
   }

   //handle tail section - do a Cipher Text Stealing

   if(size_tail == 0)
      return 0;

   //align destination buffer

   unsigned char tweak_enc[0x10] = {0};
   
   //encrypt iv using key

   int result1 = SceSblSsMgrForDriver_sceSblSsMgrAESECBEncryptForDriver(tweak, tweak_enc, 0x10, key, 0x80, 1);
   if(result1 != 0)
      return result1;

   //produce destination tail by xoring source tail with encrypted iv

   for(int i = 0; i < size_tail; i++)
      dst[size_block + i] = src[size_block + i] ^ tweak_enc[i];

   return 0;
}

//ok
int AESCBCEncryptWithKeygen_base(const unsigned char* key, unsigned char* tweak, std::uint32_t size, const unsigned char* src, unsigned char* dst, std::uint16_t key_id)
{
   std::uint16_t kid = 0; //key_id argument is ignored and is always 0

   int size_tail = size & 0xF; // get size of tail
   int size_block = size & (~0xF); // get block size aligned to 0x10 boundary
   
   //encrypt N blocks of source data with klicensee and iv

   if(size_block != 0)
   {
      int result0 = SceSblSsMgrForDriver_sceSblSsMgrAESCBCEncryptWithKeygenForDriver(src, dst, size_block, key, 0x80, tweak, kid, 1);
      if(result0 != 0)
         return result0;  
   }

   //handle tail section - do a Cipher Text Stealing

   if(size_tail == 0)
      return 0;

   //align destination buffer

   unsigned char tweak_enc[0x10] = {0};

   //encrypt iv using klicensee
     
   int result1 = SceSblSsMgrForDriver_sceSblSsMgrAESECBEncryptWithKeygenForDriver(tweak, tweak_enc, 0x10, key, 0x80, kid, 1);
   if(result1 != 0)
      return result1;

   //produce destination tail by xoring source tail with encrypted iv

   for(int i = 0; i < size_tail; i++)
      dst[size_block + i] = src[size_block + i] ^ tweak_enc[i];

   return 0;
}

//ok
int AESCBCDecryptWithKeygen_base(const unsigned char* key, unsigned char* tweak, std::uint32_t size, const unsigned char* src, unsigned char* dst, std::uint16_t key_id)
{
   std::uint16_t kid = 0; //key_id argument is ignored and is always 0

   int size_tail = size & 0xF;
   int size_block = size & (~0xF);
   
   //decrypt N blocks of source data with key and iv

   if(size_block != 0)
   {
      int result0 = SceSblSsMgrForDriver_sceSblSsMgrAESCBCDecryptWithKeygenForDriver(src, dst, size_block, key, 0x80, tweak, kid, 1);
      if(result0 != 0)
         return result0;
   }

   //handle tail section - do a Cipher Text Stealing

   if(size_tail == 0)
      return 0;

   //align destination buffer

   unsigned char tweak_enc[0x10] = {0};

   //encrypt iv using key

   int result1 = SceSblSsMgrForDriver_sceSblSsMgrAESECBEncryptWithKeygenForDriver(tweak, tweak_enc, 0x10, key, 0x80, kid, 1);
   if(result1 != 0)
      return result1;

   //produce destination tail by xoring source tail with encrypted iv

   for(int i = 0; i < size_tail; i++)
      dst[size_block + i] = src[size_block + i] ^ tweak_enc[i];

   return 0;
}

//#### GROUP 2 (possible keygen aes-cmac dec/aes-cmac enc) (technically there is no dec/enc - this is pair of same functions since cmac) ####

// FUNCTIONS ARE SIMILAR

int AESCMACEncrypt_base(const unsigned char* cmac_key, unsigned char* iv, std::uint32_t size, const unsigned char* cmac_src, unsigned char cmac_dst[0x10])
{
   throw std::runtime_error("Untested function");

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

int AESCMACDecrypt_base(const unsigned char* cmac_key, unsigned char* iv, std::uint32_t size, const unsigned char* cmac_src, unsigned char cmac_dst[0x10])
{
   throw std::runtime_error("Untested function");

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

int AESCMACEncryptWithKeygen_base(const unsigned char* cmac_key, unsigned char* iv, std::uint32_t size, const unsigned char* cmac_src, unsigned char cmac_dst[0x10], std::uint16_t key_id)
{
   throw std::runtime_error("Untested function");

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

int AESCMACDecryptWithKeygen_base(const unsigned char* cmac_key, unsigned char* iv, std::uint32_t size, const unsigned char* cmac_src, unsigned char cmac_dst[0x10], std::uint16_t key_id)
{
   throw std::runtime_error("Untested function");

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

//#### FUNCTIONS OF GROUP 3/4 are used to encrypt/decrypt icv.db ####

//base functions for xts-aes

std::uint32_t adds(std::uint32_t left, std::uint32_t right, std::uint32_t* carry)
{
   std::uint64_t l64 = left;
   std::uint64_t r64 = right;
   std::uint64_t res64 = l64 + r64;

   if((res64 & 0x0000000100000000) > 0)
      *carry = 1;
   else
      *carry = 0;

   return (std::uint32_t)res64;
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

   return (std::uint32_t)res64;
}

//this implementation is nearly identical to XTS-AES implementation here
//the only difference is that this method not only calculates multiply 2 (LFSR shift)
//but also xores source data with the LFSR register
//multiplication by 2 is implemented through addition (x1 = x0 + x0)
//https://github.com/libtom/libtomcrypt/blob/c14bcf4d302f954979f0de43f7544cf30873f5a6/src/modes/xts/xts_mult_x.c#L20
//here is more info about tweak perturbation
//https://crypto.stackexchange.com/questions/47223/xex-mode-how-to-perturb-the-tweak
int xts_mult_x_xor_data_xts(std::uint32_t* src, std::uint32_t* tweak_enc_value, std::uint32_t* dst, std::uint32_t size)
{
   std::uint32_t tweak_cpy[4] = {0};
   memcpy(tweak_cpy, tweak_enc_value, 0x10);

   while(size != 0)
   {
      dst[0] = src[0] ^ tweak_cpy[0];
      dst[1] = src[1] ^ tweak_cpy[1];
      dst[2] = src[2] ^ tweak_cpy[2];
      dst[3] = src[3] ^ tweak_cpy[3];

      src += 4;
      dst += 4;
      
      std::uint32_t carry = 0;
      tweak_cpy[0] = adds(tweak_cpy[0], tweak_cpy[0], &carry);
      tweak_cpy[1] = adcs(tweak_cpy[1], tweak_cpy[1], &carry);
      tweak_cpy[2] = adcs(tweak_cpy[2], tweak_cpy[2], &carry);
      tweak_cpy[3] = adcs(tweak_cpy[3], tweak_cpy[3], &carry);

      if(carry > 0)
         tweak_cpy[0] = tweak_cpy[0] ^ 0x87;
      
      size = size - 0x10;
   }

   return 0;
}

int xts_mult_x_xor_data_cmac(std::uint32_t* src, std::uint32_t* tweak_enc_value, std::uint32_t* dst, std::uint32_t size)
{
   std::uint32_t tweak_cpy[4] = {0};
   memcpy(tweak_cpy, tweak_enc_value, 0x10);

   while(size != 0)
   {
      dst[0] = src[0] ^ tweak_cpy[0];
      dst[1] = src[1] ^ tweak_cpy[1];
      dst[2] = src[2] ^ tweak_cpy[2];
      dst[3] = src[3] ^ tweak_cpy[3];

      std::uint32_t carry = 0;
      tweak_cpy[0] = adds(tweak_cpy[0], tweak_cpy[0], &carry);
      tweak_cpy[1] = adcs(tweak_cpy[1], tweak_cpy[1], &carry);
      tweak_cpy[2] = adcs(tweak_cpy[2], tweak_cpy[2], &carry);
      tweak_cpy[3] = adcs(tweak_cpy[3], tweak_cpy[3], &carry);

      if(carry > 0)
         tweak_cpy[0] = tweak_cpy[0] ^ 0x87;
      
      size = size - 0x10;
   }

   return 0;
}

//#### GROUP 3 (no keygen xts-aes dec/xts-aes enc) ####

//ok
int XTSAESEncrypt_base(const unsigned char* tweak, const unsigned char* dst_key, const unsigned char* tweak_enc_key, std::uint32_t key_size, std::uint32_t size, const unsigned char* src, unsigned char* dst)
{
   aes_context aes_ctx;
   unsigned char tweak_enc_value[0x10] = {0};

   //encrypt tweak

   memset(&aes_ctx, 0, sizeof(aes_context));
   aes_setkey_enc(&aes_ctx, tweak_enc_key, key_size);

   aes_crypt_ecb(&aes_ctx, AES_ENCRYPT, tweak, tweak_enc_value);

   //do tweak crypt

   xts_mult_x_xor_data_xts((std::uint32_t*)src, (std::uint32_t*)tweak_enc_value, (std::uint32_t*)dst, size);

   int result0 = SceSblSsMgrForDriver_sceSblSsMgrAESECBEncryptForDriver(dst, dst, size, dst_key, key_size, 1);
   if(result0 == 0)
      xts_mult_x_xor_data_xts((std::uint32_t*)dst, (std::uint32_t*)tweak_enc_value, (std::uint32_t*)dst, size);

   return result0;
}

//ok
int XTSAESDecrypt_base(const unsigned char* tweak, const unsigned char* dst_key, const unsigned char* tweak_enc_key, std::uint32_t key_size, std::uint32_t size, const unsigned char* src, unsigned char* dst)
{
   aes_context aes_ctx;
   unsigned char tweak_enc_value[0x10] = {0};

   //encrypt tweak

   memset(&aes_ctx, 0, sizeof(aes_context));
   aes_setkey_enc(&aes_ctx, tweak_enc_key, key_size);

   aes_crypt_ecb(&aes_ctx, AES_ENCRYPT, tweak, tweak_enc_value);

   //do tweak uncrypt

   xts_mult_x_xor_data_xts((std::uint32_t*)src, (std::uint32_t*)tweak_enc_value, (std::uint32_t*)dst, size);

   int result0 = SceSblSsMgrForDriver_sceSblSsMgrAESECBDecryptForDriver(dst, dst, size, dst_key, key_size, 1);
   if(result0 == 0)
      xts_mult_x_xor_data_xts((std::uint32_t*)dst, (std::uint32_t*)tweak_enc_value, (std::uint32_t*)dst, size);

   return result0;
}

//#### GROUP 4 (no keygen xts-cmac dec/xts-cmac enc) (technically there is no dec/enc - this is pair of same functions since cmac) ####

// FUNCTIONS ARE SIMILAR

int XTSCMACEncrypt_base(const unsigned char* tweak, const unsigned char* dst_key, const unsigned char* tweak_enc_key, std::uint32_t key_size, std::uint32_t size, const unsigned char* src, unsigned char dst[0x10])
{
   throw std::runtime_error("Untested function");

   unsigned char tweak_enc_value[0x10] = {0};

   aes_context aes_ctx;
   memset(&aes_ctx, 0, sizeof(aes_context));
   aes_setkey_enc(&aes_ctx, tweak_enc_key, key_size);

   aes_crypt_ecb(&aes_ctx, AES_ENCRYPT, tweak, tweak_enc_value);

   //not sure why this call is needed since dst will be overwritten with next cmac call
   xts_mult_x_xor_data_cmac((std::uint32_t*)src, (std::uint32_t*)tweak_enc_value, (std::uint32_t*)dst, size);

   int result0 = SceSblSsMgrForDriver_sceSblSsMgrAESCMACForDriver(src, dst, size, dst_key, key_size, 0, 1, 0);
   if(result0 == 0)
      xts_mult_x_xor_data_cmac((std::uint32_t*)dst, (std::uint32_t*)tweak_enc_value, (std::uint32_t*)dst, size);

   return result0;
}

int XTSCMACDecrypt_base(const unsigned char* tweak, const unsigned char* dst_key, const unsigned char* tweak_enc_key, std::uint32_t key_size, std::uint32_t size, const unsigned char* src, unsigned char dst[0x10])
{
   throw std::runtime_error("Untested function");

   unsigned char tweak_enc_value[0x10] = {0};
   
   aes_context aes_ctx;
   memset(&aes_ctx, 0, sizeof(aes_context));
   aes_setkey_enc(&aes_ctx, tweak_enc_key, key_size);

   aes_crypt_ecb(&aes_ctx, AES_ENCRYPT, tweak, tweak_enc_value);

   //not sure why this call is needed since dst will be overwritten with next cmac call
   xts_mult_x_xor_data_cmac((std::uint32_t*)src, (std::uint32_t*)tweak_enc_value, (std::uint32_t*)dst, size);

   int result0 = SceSblSsMgrForDriver_sceSblSsMgrAESCMACForDriver(src, dst, size, dst_key, key_size, 0, 1, 0);
   if(result0 == 0)
      xts_mult_x_xor_data_cmac((std::uint32_t*)dst, (std::uint32_t*)tweak_enc_value, (std::uint32_t*)dst, size);

   return result0;
}