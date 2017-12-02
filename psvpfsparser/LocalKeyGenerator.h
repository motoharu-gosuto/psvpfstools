#pragma once

#include <stdint.h>

#include <boost/filesystem.hpp>

#pragma pack(push, 1)

#define SEALEDKEY_MAGIC "pfsSKKey"
#define SEALEDKEY_EXPECTED_TYPE 2

typedef struct sealedkey_t
{
   uint8_t magic[8];
   uint32_t type;
   uint32_t padding;
   uint8_t iv[0x10];
   uint8_t enc_key[0x10];
   uint8_t hmac[0x20];
};

#define KEYSTONE_MAGIC "keystone"
#define KEYSTONE_EXPECTED_TYPE 2
#define KEYSTONE_EXPECTED_VERSION 1

typedef struct keystone_t
{
   uint8_t magic[8];
   uint16_t type;
   uint16_t version;
   uint8_t padding[0x14];
   uint8_t iv[0x10];
   uint8_t enc_key[0x10];
   uint8_t hmac[0x20];
};

#pragma pack(pop)

int get_sealedkey(boost::filesystem::path titleIdPath, unsigned char* dec_key);

int get_keystone(boost::filesystem::path titleIdPath, unsigned char* dec_key);