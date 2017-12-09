#pragma once

#include <cstdint>

int SceSblSsMgrForDriver_sceSblSsMgrAESCBCDecryptWithKeygenForDriver(const unsigned char* src, unsigned char* dst, int size, const unsigned char* key, int key_size, unsigned char* iv, std::uint16_t key_id, int mask_enable);

int SceSblSsMgrForDriver_sceSblSsMgrAESCBCEncryptWithKeygenForDriver(const unsigned char* src, unsigned char* dst, int size, const unsigned char* key, int key_size, unsigned char* iv, std::uint16_t key_id, int mask_enable);

int SceSblSsMgrForDriver_sceSblSsMgrAESECBEncryptWithKeygenForDriver(const unsigned char* src, unsigned char* dst, int size, const unsigned char* key, int key_size, std::uint16_t key_id, int mask_enable);

int SceSblSsMgrForDriver_sceSblSsMgrAESCBCDecryptForDriver(const unsigned char* src, unsigned char* dst, int size, const unsigned char* key, int key_size, unsigned char* iv, int mask_enable);

int SceSblSsMgrForDriver_sceSblSsMgrAESCBCEncryptForDriver(const unsigned char* src, unsigned char* dst, int size, const unsigned char* key, int key_size, unsigned char* iv, int mask_enable);

int SceSblSsMgrForDriver_sceSblSsMgrAESECBEncryptForDriver(const unsigned char* src, unsigned char* dst, int size, const unsigned char* key, int key_size, int mask_enable);

int SceSblSsMgrForDriver_sceSblSsMgrAESECBDecryptForDriver(const unsigned char* src, unsigned char* dst, int size, const unsigned char* key, int key_size, int mask_enable);

int SceSblSsMgrForDriver_sceSblSsMgrAESCMACForDriver(const unsigned char* src, unsigned char* dst, int size, const unsigned char* key, int key_size, unsigned char* iv, int mask_enable, int command_bit);

int SceSblSsMgrForDriver_sceSblSsMgrAESCMACWithKeygenForDriver(const unsigned char* src, unsigned char* dst, int size, const unsigned char* key, int key_size, unsigned char* iv, std::uint16_t key_id, int mask_enable, int command_bit);

int SceSblSsMgrForDriver_sceSblSsMgrHMACSHA1ForDriver(const unsigned char* src, unsigned char* dst, int size, const unsigned char* key, unsigned char* iv, int mask_enable, int command_bit);