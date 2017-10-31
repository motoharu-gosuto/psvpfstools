#pragma once

#include <stdint.h>
#include <string>

int scePfsUtilGetSecret(unsigned char* secret, const unsigned char* klicensee, uint32_t salt0, uint16_t flag, uint32_t salt1, uint16_t key_id);