#pragma once

#include <cstdint>
#include <string>

int scePfsUtilGetSecret(unsigned char* secret, const unsigned char* klicensee, std::uint32_t files_salt, std::uint16_t flag, std::uint32_t unicv_page_salt, std::uint16_t key_id);