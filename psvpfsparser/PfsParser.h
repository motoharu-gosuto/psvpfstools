#pragma once

#include <memory>
#include <iostream>

#include <boost/filesystem.hpp>

#include "ICryptoOperations.h"
#include "IF00DKeyEncryptor.h"

#include "FilesDbParser.h"
#include "UnicvDbParser.h"
#include "PfsPageMapper.h"

class PfsParser
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
   PfsParser(std::shared_ptr<ICryptoOperations> cryptops, std::shared_ptr<IF00DKeyEncryptor> iF00D, std::ostream& output, const unsigned char* klicensee, boost::filesystem::path titleIdPath);

public:
   int parse();

public:
   const std::unique_ptr<FilesDbParser>& get_filesDbParser() const;

   const std::unique_ptr<UnicvDbParser>& get_unicvDbParser() const;

   const std::unique_ptr<PfsPageMapper>& get_pageMapper() const;
};