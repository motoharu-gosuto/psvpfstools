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

#include "PfsCryptEngine.h"

struct sce_ng_pfs_header_t;
class sce_idb_base_t;
struct sce_ng_pfs_file_t;
struct sce_ng_pfs_dir_t;
class sce_iftbl_base_t;
class sig_tbl_t;

class PfsFile
{
private:
   std::shared_ptr<ICryptoOperations> m_cryptops;
   std::shared_ptr<IF00DKeyEncryptor> m_iF00D;
   std::ostream& m_output;
   unsigned char m_klicensee[0x10];
   boost::filesystem::path m_titleIdPath;

private:
   CryptEngineData m_data;
   CryptEngineSubctx m_sub_ctx;
   std::vector<std::uint8_t> m_signatureTable;

public:
   PfsFile(std::shared_ptr<ICryptoOperations> cryptops, std::shared_ptr<IF00DKeyEncryptor> iF00D, std::ostream& output, 
           const unsigned char* klicensee, boost::filesystem::path titleIdPath);

private:
   int init_crypt_ctx(CryptEngineWorkCtx* work_ctx, const sce_ng_pfs_header_t& ngpfs, const sce_ng_pfs_file_t& file, std::shared_ptr<sce_iftbl_base_t> table, sig_tbl_t& block, std::uint32_t sector_base, std::uint32_t tail_size, unsigned char* source);

   int decrypt_icv_file(boost::filesystem::path destination_root, const sce_ng_pfs_file_t& file, const sce_junction& filepath, const sce_ng_pfs_header_t& ngpfs, std::shared_ptr<sce_iftbl_base_t> table);

   int decrypt_unicv_file(boost::filesystem::path destination_root, const sce_ng_pfs_file_t& file, const sce_junction& filepath, const sce_ng_pfs_header_t& ngpfs, std::shared_ptr<sce_iftbl_base_t> table);

public:
   int decrypt_file(boost::filesystem::path destination_root, const sce_ng_pfs_file_t& file, const sce_junction& filepath, const sce_ng_pfs_header_t& ngpfs, std::shared_ptr<sce_iftbl_base_t> table);
};

class PfsFilesystem
{
private:
   std::shared_ptr<ICryptoOperations> m_cryptops;
   std::shared_ptr<IF00DKeyEncryptor> m_iF00D;
   std::ostream& m_output;
   unsigned char m_klicensee[0x10];
   boost::filesystem::path m_titleIdPath;

public:
   PfsFilesystem(std::shared_ptr<ICryptoOperations> cryptops, std::shared_ptr<IF00DKeyEncryptor> iF00D, std::ostream& output, 
                 const unsigned char* klicensee, boost::filesystem::path titleIdPath);

private:
   std::vector<sce_ng_pfs_file_t>::const_iterator find_file_by_path(const std::vector<sce_ng_pfs_file_t>& files, const sce_junction& p);

public:
   int decrypt_files(boost::filesystem::path destTitleIdPath, const sce_ng_pfs_header_t& ngpfs, const std::vector<sce_ng_pfs_file_t>& files, const std::vector<sce_ng_pfs_dir_t>& dirs, const std::unique_ptr<sce_idb_base_t>& fdb, const std::map<std::uint32_t, sce_junction>& pageMap, const std::set<sce_junction>& emptyFiles);
};
