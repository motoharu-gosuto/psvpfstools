#pragma once

#include <stdint.h>

int AESCBCEncrypt_base(const unsigned char* key, unsigned char* iv, uint32_t size, const unsigned char* src, unsigned char* dst);

int AESCBCDecrypt_base(const unsigned char* key, unsigned char* iv, uint32_t size, const unsigned char* src, unsigned char* dst);

int AESCBCDecryptWithKeygen_base(const unsigned char* key, unsigned char* iv, uint32_t size, const unsigned char* src, unsigned char* dst, uint16_t key_id);

int AESCBCEncryptWithKeygen_base(const unsigned char* klicensee, unsigned char* iv, uint32_t size, const unsigned char* src, unsigned char* dst, uint16_t key_id);

int AESCMAC_base_1(const unsigned char* cmac_key, unsigned char* iv, uint32_t size, const unsigned char* cmac_src, unsigned char* cmac_dst);

int AESCMAC_base_2(const unsigned char* cmac_key, unsigned char* iv, uint32_t size, const unsigned char* cmac_src, unsigned char* cmac_dst);

int AESCMACWithKeygen_base_1(const unsigned char* cmac_key, unsigned char* iv, uint32_t size, const unsigned char* cmac_src, unsigned char* cmac_dst, uint16_t key_id);

int AESCMACWithKeygen_base_2(const unsigned char* cmac_key, unsigned char* iv, uint32_t size, const unsigned char* cmac_src, unsigned char* cmac_dst, uint16_t key_id);

int AESCMACDecryptSw_base(const unsigned char* subkey, const unsigned char* dst_key, const unsigned char* subkey_key, uint32_t key_size, uint32_t size, const unsigned char* src, unsigned char* dst);

int AESCMACEncryptSw_base(const unsigned char* subkey, const unsigned char* dst_key, const unsigned char* subkey_key, uint32_t key_size, uint32_t size, const unsigned char* src, unsigned char* dst);

int AESCMACSw_base_1(const unsigned char* subkey, const unsigned char* dst_key, const unsigned char* subkey_key, uint32_t keysize, uint32_t size, const unsigned char* src, unsigned char* dst);

int AESCMACSw_base_2(const unsigned char* subkey, const unsigned char* dst_key, const unsigned char* subkey_key, uint32_t keysize, uint32_t size, const unsigned char* src, unsigned char* dst);