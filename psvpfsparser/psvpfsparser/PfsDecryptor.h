#pragma once

#include <stdint.h>

#include <string>
#include <map>
#include <vector>

#include <boost/filesystem.hpp>

struct sce_ng_pfs_header_t;
struct scei_rodb_t;
struct sce_ng_pfs_file_t;

void bruteforce_map(std::string title_id_path, unsigned char* klicensee, sce_ng_pfs_header_t& ngpfs, scei_rodb_t& fdb, std::map<uint32_t, std::string>& pageMap);

void load_page_map(std::string filepath, std::map<uint32_t, std::string>& pageMap);

void decrypt_files(boost::filesystem::path title_id_path, boost::filesystem::path destination_root, unsigned char* klicensee, sce_ng_pfs_header_t& ngpfs, std::vector<sce_ng_pfs_file_t>& files, scei_rodb_t& fdb, std::map<uint32_t, std::string>& pageMap);