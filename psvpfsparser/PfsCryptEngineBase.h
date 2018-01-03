#pragma once

#include <cstdint>

//#### GROUP 1 (hw dec/enc) ####

int AESCBCEncrypt_base(const unsigned char* key, unsigned char* iv, std::uint32_t size, const unsigned char* src, unsigned char* dst);

int AESCBCDecrypt_base(const unsigned char* key, unsigned char* iv, std::uint32_t size, const unsigned char* src, unsigned char* dst);

int AESCBCDecryptWithKeygen_base(const unsigned char* key, unsigned char* iv, std::uint32_t size, const unsigned char* src, unsigned char* dst, std::uint16_t key_id);

int AESCBCEncryptWithKeygen_base(const unsigned char* klicensee, unsigned char* iv, std::uint32_t size, const unsigned char* src, unsigned char* dst, std::uint16_t key_id);

//#### GROUP 2 (hw cmac) ####

int AESCMAC_base_1(const unsigned char* cmac_key, unsigned char* iv, std::uint32_t size, const unsigned char* cmac_src, unsigned char* cmac_dst);

int AESCMAC_base_2(const unsigned char* cmac_key, unsigned char* iv, std::uint32_t size, const unsigned char* cmac_src, unsigned char* cmac_dst);

//#### GROUP 3 (sw dec/enc) ####

int AESCMACWithKeygen_base_1(const unsigned char* cmac_key, unsigned char* iv, std::uint32_t size, const unsigned char* cmac_src, unsigned char* cmac_dst, std::uint16_t key_id);

int AESCMACWithKeygen_base_2(const unsigned char* cmac_key, unsigned char* iv, std::uint32_t size, const unsigned char* cmac_src, unsigned char* cmac_dst, std::uint16_t key_id);

int AESXTSDecryptSw_base(const unsigned char* tweak, const unsigned char* dst_key, const unsigned char* tweak_enc_key, std::uint32_t key_size, std::uint32_t size, const unsigned char* src, unsigned char* dst);

int AESXTSEncryptSw_base(const unsigned char* tweak, const unsigned char* dst_key, const unsigned char* tweak_enc_key, std::uint32_t key_size, std::uint32_t size, const unsigned char* src, unsigned char* dst);

//#### GROUP 4 (sw cmac) ####

int AESCMACSw_base_1(const unsigned char* tweak, const unsigned char* dst_key, const unsigned char* tweak_enc_key, std::uint32_t key_size, std::uint32_t size, const unsigned char* src, unsigned char* dst);

int AESCMACSw_base_2(const unsigned char* tweak, const unsigned char* dst_key, const unsigned char* tweak_enc_key, std::uint32_t key_size, std::uint32_t size, const unsigned char* src, unsigned char* dst);