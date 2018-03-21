#include "DefaultCryptoOperations.h"

int DefaultCryptoOperations::aes_cbc_encrypt(const unsigned char* src, unsigned char* dst, int size, const unsigned char* key, int key_size, unsigned char* iv) const
{
   return 0;
}

int DefaultCryptoOperations::aes_cbc_decrypt(const unsigned char* src, unsigned char* dst, int size, const unsigned char* key, int key_size, unsigned char* iv) const  
{
   return 0;
}

int DefaultCryptoOperations::aes_ecb_encrypt(const unsigned char* src, unsigned char* dst, int size, const unsigned char* key, int key_size) const  
{
   return 0;
}

int DefaultCryptoOperations::aes_ecb_decrypt(const unsigned char* src, unsigned char* dst, int size, const unsigned char* key, int key_size) const
{
   return 0;
}
   
int DefaultCryptoOperations::aes_cmac(const unsigned char* src, unsigned char* dst, int size, const unsigned char* key, int key_size) const
{
   return 0;
}
   
int DefaultCryptoOperations::sha1(const unsigned char *source, int size, unsigned char* result) const
{
   return 0;
}

int DefaultCryptoOperations::hmac_sha1(const unsigned char* key, int key_len, const unsigned char* data, int data_len, unsigned char* digest) const
{
   return 0;
}