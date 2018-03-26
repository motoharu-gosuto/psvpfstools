#pragma once

#include <cstdint>

#include <string>
#include <map>
#include <vector>
#include <set>
#include <memory>

#include <boost/filesystem.hpp>

#include "IF00DKeyEncryptor.h"
#include "ICryptoOperations.h"

#include "Utils.h"

struct sce_ng_pfs_header_t;
class sce_idb_base_t;
struct sce_ng_pfs_file_t;
struct sce_ng_pfs_dir_t;

int bruteforce_map(std::shared_ptr<ICryptoOperations> cryptops, std::shared_ptr<IF00DKeyEncryptor> iF00D, boost::filesystem::path titleIdPath, unsigned char* klicensee, sce_ng_pfs_header_t& ngpfs, std::shared_ptr<sce_idb_base_t> fdb, std::map<std::uint32_t, sce_junction>& pageMap, std::set<sce_junction>& emptyFiles);

int load_page_map(boost::filesystem::path filepath, std::map<std::uint32_t, std::string>& pageMap);

int decrypt_files(std::shared_ptr<ICryptoOperations> cryptops, std::shared_ptr<IF00DKeyEncryptor> iF00D, boost::filesystem::path titleIdPath, boost::filesystem::path destTitleIdPath, unsigned char* klicensee, sce_ng_pfs_header_t& ngpfs, std::vector<sce_ng_pfs_file_t>& files, std::vector<sce_ng_pfs_dir_t>& dirs, std::shared_ptr<sce_idb_base_t> fdb, std::map<std::uint32_t, sce_junction>& pageMap, std::set<sce_junction>& emptyFiles);