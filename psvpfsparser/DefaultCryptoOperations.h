#include "ICryptoOperations.h"

class DefaultCryptoOperations : public ICryptoOperations
{
public:
   int aes_cbc_encrypt(const unsigned char* src, unsigned char* dst, int size, const unsigned char* key, int key_size, unsigned char* iv) const override;
   int aes_cbc_decrypt(const unsigned char* src, unsigned char* dst, int size, const unsigned char* key, int key_size, unsigned char* iv) const override;
   
   int aes_ecb_encrypt(const unsigned char* src, unsigned char* dst, int size, const unsigned char* key, int key_size) const override;
   int aes_ecb_decrypt(const unsigned char* src, unsigned char* dst, int size, const unsigned char* key, int key_size) const override;
   
   int aes_cmac(const unsigned char* src, unsigned char* dst, int size, const unsigned char* key, int key_size) const override;
   
   int sha1(const unsigned char *source, int size, unsigned char* result) const override;
   int hmac_sha1(const unsigned char* key, int key_len, const unsigned char* data, int data_len, unsigned char* digest) const override;
};