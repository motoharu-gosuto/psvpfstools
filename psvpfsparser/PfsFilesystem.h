#pragma once

#include <memory>

#include <boost/filesystem.hpp>

#include "IF00DKeyEncryptor.h"
#include "ICryptoOperations.h"

#include "FilesDbParser.h"
#include "UnicvDbParser.h"
#include "PfsPageMapper.h"

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
