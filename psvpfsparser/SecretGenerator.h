#pragma once

#include <stdint.h>
#include <string>

int scePfsUtilGetSecret(unsigned char* secret, const unsigned char* klicensee, uint32_t files_salt, uint16_t flag, uint32_t unicv_page_salt, uint16_t key_id);

struct sce_ng_pfs_header_t;

int secret_type_to_flag(sce_ng_pfs_header_t& header);