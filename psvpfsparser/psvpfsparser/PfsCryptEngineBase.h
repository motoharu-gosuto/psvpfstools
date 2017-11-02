#pragma once

#include <stdint.h>

int AESCBCEncrypt_base_219D8AC(const unsigned char* key, unsigned char* iv, uint32_t size, const unsigned char* src, unsigned char* dst);

int AESCBCDecrypt_base_219D950(const unsigned char* key, unsigned char* iv, uint32_t size, const unsigned char* src, unsigned char* dst);

int AESCBCDecryptWithKeygen_base_219DAAC(const unsigned char* key, unsigned char* iv, uint32_t size, const unsigned char* src, unsigned char* dst, uint16_t key_id);

int AESCBCEncryptWithKeygen_base_219D9F4(const unsigned char* klicensee, unsigned char* iv, uint32_t size, const unsigned char* src, unsigned char* dst, uint16_t key_id);

int AESCMAC_base_1_219DC08(const unsigned char* cmac_key, unsigned char* iv, uint32_t size, const unsigned char* cmac_src, unsigned char* cmac_dst);

int AESCMAC_base_2_219DB64(const unsigned char* cmac_key, unsigned char* iv, uint32_t size, const unsigned char* cmac_src, unsigned char* cmac_dst);

int AESCMACWithKeygen_base_1_219DCAC(const unsigned char* cmac_key, unsigned char* iv, uint32_t size, const unsigned char* cmac_src, unsigned char* cmac_dst, uint16_t key_id);

int AESCMACWithKeygen_base_2_219DD64(const unsigned char* cmac_key, unsigned char* iv, uint32_t size, const unsigned char* cmac_src, unsigned char* cmac_dst, uint16_t key_id);

int AESCMACDecryptSw_base_219D714(const unsigned char* subkey, const unsigned char* dst_key, const unsigned char* subkey_key, uint32_t key_size, uint32_t size, const unsigned char* src, unsigned char* dst);

int AESCMACEncryptSw_base_219D694(const unsigned char* subkey, const unsigned char* dst_key, const unsigned char* subkey_key, uint32_t key_size, uint32_t size, const unsigned char* src, unsigned char* dst);

int AESCMACSw_base_1_219D794(const unsigned char* subkey, const unsigned char* dst_key, const unsigned char* subkey_key, uint32_t keysize, uint32_t size, const unsigned char* src, unsigned char* dst);

int AESCMACSw_base_2_219D820(const unsigned char* subkey, const unsigned char* dst_key, const unsigned char* subkey_key, uint32_t keysize, uint32_t size, const unsigned char* src, unsigned char* dst);