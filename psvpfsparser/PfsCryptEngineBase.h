#pragma once

#include <cstdint>

//#### GROUP 1 (hw dec/enc) ####

int AESCBCEncrypt_base(const unsigned char* key, unsigned char* iv, std::uint32_t size, const unsigned char* src, unsigned char* dst);

int AESCBCDecrypt_base(const unsigned char* key, unsigned char* iv, std::uint32_t size, const unsigned char* src, unsigned char* dst);

int AESCBCEncryptWithKeygen_base(const unsigned char* klicensee, unsigned char* iv, std::uint32_t size, const unsigned char* src, unsigned char* dst, std::uint16_t key_id);

int AESCBCDecryptWithKeygen_base(const unsigned char* key, unsigned char* iv, std::uint32_t size, const unsigned char* src, unsigned char* dst, std::uint16_t key_id);

//#### GROUP 2 (hw cmac) ####

int AESCMACEncrypt_base(const unsigned char* cmac_key, unsigned char* iv, std::uint32_t size, const unsigned char* cmac_src, unsigned char* cmac_dst);

int AESCMACDecrypt_base(const unsigned char* cmac_key, unsigned char* iv, std::uint32_t size, const unsigned char* cmac_src, unsigned char* cmac_dst);

int AESCMACEncryptWithKeygen_base(const unsigned char* cmac_key, unsigned char* iv, std::uint32_t size, const unsigned char* cmac_src, unsigned char* cmac_dst, std::uint16_t key_id);

int AESCMACDecryptWithKeygen_base(const unsigned char* cmac_key, unsigned char* iv, std::uint32_t size, const unsigned char* cmac_src, unsigned char* cmac_dst, std::uint16_t key_id);

//#### GROUP 3 (no keygen xts-aes dec/xts-aes enc) ####

int XTSAESEncrypt_base(const unsigned char* tweak, const unsigned char* dst_key, const unsigned char* tweak_enc_key, std::uint32_t key_size, std::uint32_t size, const unsigned char* src, unsigned char* dst);

int XTSAESDecrypt_base(const unsigned char* tweak, const unsigned char* dst_key, const unsigned char* tweak_enc_key, std::uint32_t key_size, std::uint32_t size, const unsigned char* src, unsigned char* dst);

//#### GROUP 4 (no keygen xts-cmac dec/xts-cmac enc) (technically there is no dec/enc - this is pair of same functions since cmac) ####

int XTSCMACEncrypt_base(const unsigned char* tweak, const unsigned char* dst_key, const unsigned char* tweak_enc_key, std::uint32_t key_size, std::uint32_t size, const unsigned char* src, unsigned char* dst);

int XTSCMACDecrypt_base(const unsigned char* tweak, const unsigned char* dst_key, const unsigned char* tweak_enc_key, std::uint32_t key_size, std::uint32_t size, const unsigned char* src, unsigned char* dst);