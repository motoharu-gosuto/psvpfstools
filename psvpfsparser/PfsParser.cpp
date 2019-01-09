#include "PfsParser.h"

#include <memory>

PfsParser::PfsParser(std::shared_ptr<ICryptoOperations> cryptops, std::shared_ptr<IF00DKeyEncryptor> iF00D, std::ostream& output, const unsigned char* klicensee, boost::filesystem::path titleIdPath)
   : m_cryptops(cryptops), m_iF00D(iF00D), m_output(output), m_titleIdPath(titleIdPath)
{
   memcpy(m_klicensee, klicensee, 0x10);

   m_filesDbParser = std::unique_ptr<FilesDbParser>(new FilesDbParser(cryptops, iF00D, output, klicensee, titleIdPath));

   m_unicvDbParser = std::unique_ptr<UnicvDbParser>(new UnicvDbParser(titleIdPath, output));

   m_pageMapper = std::unique_ptr<PfsPageMapper>(new PfsPageMapper(cryptops, iF00D, output, klicensee, titleIdPath));
}

int PfsParser::parse()
{
   if(m_filesDbParser->parse() < 0)
      return -1;

   if(m_unicvDbParser->parse() < 0)
      return -1;

   if(m_pageMapper->bruteforce_map(m_filesDbParser, m_unicvDbParser) < 0)
      return -1;
   
   return 0;
}

const std::unique_ptr<FilesDbParser>& PfsParser::get_filesDbParser() const
{
   return m_filesDbParser;
}

const std::unique_ptr<UnicvDbParser>& PfsParser::get_unicvDbParser() const
{
   return m_unicvDbParser;
}

const std::unique_ptr<PfsPageMapper>& PfsParser::get_pageMapper() const
{
   return m_pageMapper;
}