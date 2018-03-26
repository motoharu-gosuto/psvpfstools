#pragma once

#include <map>

#include <boost/filesystem.hpp>

#include "IF00DKeyEncryptor.h"

class F00DFileKeyEncryptor : public IF00DKeyEncryptor
{
private:
   boost::filesystem::path m_filePath;

   std::map<std::string, std::string> m_keyCache;
   bool m_isCacheLoaded;

public:
   F00DFileKeyEncryptor(boost::filesystem::path filePath);

private:
   int load_cache_flat_file();

   int load_cache_json_file();

   int load_cache_file();

public:
   int encrypt_key(const unsigned char* key, int key_size, unsigned char* drv_key) override;

   void print_cache(std::ostream& os, std::string sep = "\t") const override;
};