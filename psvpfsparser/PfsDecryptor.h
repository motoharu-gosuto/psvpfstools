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

#include "FilesDbParser.h"
#include "UnicvDbParser.h"
#include "PfsPageMapper.h"
#include "PfsCryptEngine.h"

class PfsFile
{
private:
   std::shared_ptr<ICryptoOperations> m_cryptops;
   std::shared_ptr<IF00DKeyEncryptor> m_iF00D;
   std::ostream& m_output;
   unsigned char m_klicensee[0x10];
   boost::filesystem::path m_titleIdPath;

private:
   const sce_ng_pfs_file_t& m_file;
   const sce_junction& m_filepath;
   const sce_ng_pfs_header_t& m_ngpfs;
   std::shared_ptr<sce_iftbl_base_t> m_table;

private:
   mutable CryptEngineData m_data;
   mutable CryptEngineSubctx m_sub_ctx;
   mutable std::vector<std::uint8_t> m_signatureTable;

public:
   PfsFile(std::shared_ptr<ICryptoOperations> cryptops, std::shared_ptr<IF00DKeyEncryptor> iF00D, std::ostream& output, 
           const unsigned char* klicensee, boost::filesystem::path titleIdPath,
           const sce_ng_pfs_file_t& file, const sce_junction& filepath, const sce_ng_pfs_header_t& ngpfs, std::shared_ptr<sce_iftbl_base_t> table);

private:
   int init_crypt_ctx(CryptEngineWorkCtx* work_ctx, const sce_ng_pfs_header_t& ngpfs, const sce_ng_pfs_file_t& file, std::shared_ptr<sce_iftbl_base_t> table, sig_tbl_t& block, std::uint32_t sector_base, std::uint32_t tail_size, unsigned char* source) const;

   int decrypt_icv_file(boost::filesystem::path destination_root) const;

   int decrypt_unicv_file(boost::filesystem::path destination_root) const;

public:
   int decrypt_file(boost::filesystem::path destination_root) const;
};

class PfsFilesystem
{
private:
   std::shared_ptr<ICryptoOperations> m_cryptops;
   std::shared_ptr<IF00DKeyEncryptor> m_iF00D;
   std::ostream& m_output;
   unsigned char m_klicensee[0x10];
   boost::filesystem::path m_titleIdPath;

private:
   std::unique_ptr<FilesDbParser> m_filesDbParser;
   std::unique_ptr<UnicvDbParser> m_unicvDbParser;
   std::unique_ptr<PfsPageMapper> m_pageMapper;

public:
   PfsFilesystem(std::shared_ptr<ICryptoOperations> cryptops, std::shared_ptr<IF00DKeyEncryptor> iF00D, std::ostream& output, 
                 const unsigned char* klicensee, boost::filesystem::path titleIdPath);

private:
   std::vector<sce_ng_pfs_file_t>::const_iterator find_file_by_path(const std::vector<sce_ng_pfs_file_t>& files, const sce_junction& p) const;

public:
   int mount();

   int decrypt_files(boost::filesystem::path destTitleIdPath) const;
};
