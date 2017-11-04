#include "SceSblSsMgrForDriver.h"

#include "F00DKeyEncryptor.h"

#include "aes.h"
#include "sha1.h"

//##### WITH KEYGEN CRYPTO FUNCTIONS #####

//this function is tested and works
int SceSblSsMgrForDriver_sceSblSsMgrAESCBCDecryptWithKeygenForDriver(const unsigned char* src, unsigned char* dst, int size, const unsigned char* key, int key_size, unsigned char* iv, uint16_t key_id, int mask_enable)
{
   F00DKeyEncryptor* ec = get_F00D_encryptor();
   unsigned char drv_key[0x20] = {0}; //use max possible buffer
   if(ec->encrypt_key(key, key_size, drv_key) < 0)
      return -1;

   aes_context aes_ctx;
   memset(&aes_ctx, 0, sizeof(aes_ctx));
   aes_setkey_dec(&aes_ctx, drv_key, key_size);
   aes_crypt_cbc(&aes_ctx, AES_DECRYPT, size, iv, src,dst);

   return 0;
}

//this function is tested and works
int SceSblSsMgrForDriver_sceSblSsMgrAESCBCEncryptWithKeygenForDriver(const unsigned char* src, unsigned char* dst, int size, const unsigned char* key, int key_size, unsigned char* iv, uint16_t key_id, int mask_enable)
{
   F00DKeyEncryptor* ec = get_F00D_encryptor();
   unsigned char drv_key[0x20] = {0}; //use max possible buffer
   if(ec->encrypt_key(key, key_size, drv_key) < 0)
      return -1;

   aes_context aes_ctx;
   memset(&aes_ctx, 0, sizeof(aes_ctx));
   aes_setkey_enc(&aes_ctx, drv_key, key_size);
   aes_crypt_cbc(&aes_ctx, AES_ENCRYPT, size, iv, src,dst);

   return 0;
}

//this function is tested and works
int SceSblSsMgrForDriver_sceSblSsMgrAESECBEncryptWithKeygenForDriver(const unsigned char* src, unsigned char* dst, int size, const unsigned char* key, int key_size, uint16_t key_id, int mask_enable)
{
   F00DKeyEncryptor* ec = get_F00D_encryptor();
   unsigned char drv_key[0x20] = {0}; //use max possible buffer
   if(ec->encrypt_key(key, key_size, drv_key) < 0)
      return -1;

   aes_context aes_ctx;
   memset(&aes_ctx, 0, sizeof(aes_ctx));
   aes_setkey_enc(&aes_ctx, drv_key, key_size);
   aes_crypt_ecb(&aes_ctx, AES_ENCRYPT, src, dst);

   return 0;
}

//##### NORMAL CRYPTO FUNCTIONS #####

// aes-cbc

//not implemented
int SceSblSsMgrForDriver_sceSblSsMgrAESCBCDecryptForDriver(const unsigned char* src, unsigned char* dst, int size, const unsigned char* key, int key_size, unsigned char* iv, int mask_enable)
{
   throw std::runtime_error("not implemented");
}

//not implemented
int SceSblSsMgrForDriver_sceSblSsMgrAESCBCEncryptForDriver(const unsigned char* src, unsigned char* dst, int size, const unsigned char* key, int key_size, unsigned char* iv, int mask_enable)
{
   throw std::runtime_error("not implemented");
}

// aes-ecb

//not implemented
int SceSblSsMgrForDriver_sceSblSsMgrAESECBEncryptForDriver(const unsigned char* src, unsigned char* dst, int size, const unsigned char* key, int key_size, int mask_enable)
{
   throw std::runtime_error("not implemented");
}

//not implemented
int SceSblSsMgrForDriver_sceSblSsMgrAESECBDecryptForDriver(const unsigned char* src, unsigned char* dst, int size, const unsigned char* key, int key_size, int mask_enable)
{
   throw std::runtime_error("not implemented");
}

//##### CMAC FUNCTIONS #####

//not implemented
int SceSblSsMgrForDriver_sceSblSsMgrAESCMACForDriver(const unsigned char* src, unsigned char* dst, int size, const unsigned char* key, int key_size, unsigned char* iv, int mask_enable, int command_bit)
{
   throw std::runtime_error("not implemented");
}

//not tested
int SceSblSsMgrForDriver_sceSblSsMgrAESCMACWithKeygenForDriver(const unsigned char* src, unsigned char* dst, int size, const unsigned char* key, int key_size, unsigned char* iv, uint16_t key_id, int mask_enable, int command_bit)
{
   F00DKeyEncryptor* ec = get_F00D_encryptor();
   unsigned char drv_key[0x20] = {0}; //use max possible buffer
   if(ec->encrypt_key(key, key_size, drv_key) < 0)
      return -1;

   aes_context aes_ctx;
   memset(&aes_ctx, 0, sizeof(aes_ctx));
   aes_setkey_enc(&aes_ctx, drv_key, key_size);

   unsigned char* src_cpy = new unsigned char[size];
   memcpy(src_cpy, src, size);
   aes_cmac(&aes_ctx, size, src_cpy, dst);
   delete [] src_cpy;

   return 0;
}

//##### NORMAL HASH FUNCTIONS #####

//this function is tested and works
int SceSblSsMgrForDriver_sceSblSsMgrHMACSHA1ForDriver(const unsigned char* src, unsigned char* dst, int size, const unsigned char* key, unsigned char* iv, int mask_enable, int command_bit)
{
   if(iv != 0)
      throw std::runtime_error("unsupported iv");

   if(mask_enable != 1)
      throw std::runtime_error("unsupported mask_enable");

   if(command_bit != 0)
      throw std::runtime_error("unsupported command_bit");

   sha1_hmac(key, 0x14, src, size, dst);

   return 0;
}