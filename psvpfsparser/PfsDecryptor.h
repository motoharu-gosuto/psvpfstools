#pragma once

#include <stdint.h>

#include <string>
#include <map>
#include <vector>

#include <boost/filesystem.hpp>

struct sce_ng_pfs_header_t;
struct scei_rodb_t;
struct sce_ng_pfs_file_t;

int bruteforce_map(boost::filesystem::path titleIdPath, unsigned char* klicensee, sce_ng_pfs_header_t& ngpfs, scei_rodb_t& fdb, std::map<uint32_t, std::string>& pageMap);

int load_page_map(boost::filesystem::path filepath, std::map<uint32_t, std::string>& pageMap);

int decrypt_files(boost::filesystem::path titleIdPath, boost::filesystem::path destTitleIdPath, unsigned char* klicensee, sce_ng_pfs_header_t& ngpfs, std::vector<sce_ng_pfs_file_t>& files, scei_rodb_t& fdb, std::map<uint32_t, std::string>& pageMap);