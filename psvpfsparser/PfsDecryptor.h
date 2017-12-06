#pragma once

#include <stdint.h>

#include <string>
#include <map>
#include <vector>
#include <set>
#include <memory>

#include <boost/filesystem.hpp>

struct sce_ng_pfs_header_t;
class scei_db_base_t;
struct sce_ng_pfs_file_t;
struct sce_ng_pfs_dir_t;

int bruteforce_map(boost::filesystem::path titleIdPath, unsigned char* klicensee, sce_ng_pfs_header_t& ngpfs, std::shared_ptr<scei_db_base_t> fdb, std::map<uint32_t, std::string>& pageMap, std::set<std::string>& emptyFiles);

int load_page_map(boost::filesystem::path filepath, std::map<uint32_t, std::string>& pageMap);

int decrypt_files(boost::filesystem::path titleIdPath, boost::filesystem::path destTitleIdPath, unsigned char* klicensee, sce_ng_pfs_header_t& ngpfs, std::vector<sce_ng_pfs_file_t>& files, std::vector<sce_ng_pfs_dir_t>& dirs, std::shared_ptr<scei_db_base_t> fdb, std::map<uint32_t, std::string>& pageMap, std::set<std::string>& emptyFiles);