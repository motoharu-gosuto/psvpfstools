#pragma once

#include <stdint.h>

extern uint8_t sealedkey_retail_key[0x10];

extern uint8_t sealedkey_debug_key[0x10];

extern uint8_t keystone_hmac_secret1[0x20];

extern uint8_t keystone_hmac_secret2[0x20];

extern uint8_t keystone_debugkey[0x20];

extern uint8_t PFS_EncKey[0x10];