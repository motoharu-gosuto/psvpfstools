#pragma once

#include <stdint.h>

#include <string>
#include <map>

struct sce_ng_pfs_header_t;
struct scei_rodb_t;

void bruteforce_map(std::string title_id_path, unsigned char* klicensee, sce_ng_pfs_header_t& ngpfs, scei_rodb_t& fdb, std::map<uint32_t, std::string>& pageMap);