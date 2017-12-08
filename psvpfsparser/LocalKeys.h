#pragma once

#include <stdint.h>

extern uint8_t sealedkey_retail_key[0x10];

extern uint8_t sealedkey_debug_key[0x10];

extern uint8_t keystone_hmac_secret[0x20];

extern uint8_t keystone_debug_key[0x20];

extern uint8_t passcode_hmac_secret[0x20];

extern uint8_t passcode_debug_key[0x20];

extern uint8_t PFS_EncKey[0x10];