#include <string>
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <iomanip>

#include <boost/filesystem.hpp>
#include <boost/algorithm/string.hpp>

#include <libzRIF/zRIF/rif.h>
#include <libzRIF/zRIF/licdec.h>

#include "Utils.h"

#include "UnicvDbParser.h"
#include "FilesDbParser.h"
#include "PfsDecryptor.h"
#include "F00DKeyEncryptor.h"
#include "PsvPfsParserConfig.h"
#include "LocalKeyGenerator.h"

int execute(PsvPfsParserConfig& cfg)
{
   //trim slashes in source path
   
   boost::filesystem::path titleIdPath(cfg.title_id_src);
   std::string titleIdGen = titleIdPath.generic_string();
   boost::algorithm::trim_right_if(titleIdGen, [](char c){return c == '/';});
   titleIdPath = boost::filesystem::path(titleIdGen);

   //trim slashes in dest path
   boost::filesystem::path destTitleIdPath(cfg.title_id_dst);
   std::string destTitleIdPathGen = destTitleIdPath.generic_string();
   boost::algorithm::trim_right_if(destTitleIdPathGen, [](char c){return c == '/';});
   destTitleIdPath = boost::filesystem::path(destTitleIdPathGen);

   unsigned char klicensee[0x10] = {0};
   if(cfg.klicensee.length() > 0)
   {
      if(string_to_byte_array(cfg.klicensee, 0x10, klicensee) < 0)
      {
         std::cout << "Failed to parse klicensee" << std::endl;
         return -1;
      }
   }
   else if(cfg.zRIF.length() > 0)
   {
      std::shared_ptr<SceNpDrmLicense> lic = decode_license_np(cfg.zRIF);
      if(!lic)
      {
         std::cout << "Failed to decode zRIF string" << std::endl;
         return -1;
      }
      memcpy(klicensee, lic->key, 0x10);
   }
   else
   {
      std::cout << "using sealedkey..." << std::endl;
      
      if(get_sealedkey(cfg.title_id_src, klicensee) < 0)
         return -1;
   }

   set_F00D_url(cfg.f00d_url);

   if(!boost::filesystem::exists(titleIdPath))
   {
      std::cout << "Root directory does not exist" << std::endl;
      return -1;
   }

   sce_ng_pfs_header_t header;
   std::vector<sce_ng_pfs_file_t> files;
   std::vector<sce_ng_pfs_dir_t> dirs;
   if(parseFilesDb(klicensee, titleIdPath, header, files, dirs) < 0)
      return -1;

   std::shared_ptr<sce_idb_base_t> unicv;
   if(parseUnicvDb(titleIdPath, unicv) < 0)
      return -1;

   std::map<std::uint32_t, sce_junction> pageMap;
   std::set<sce_junction> emptyFiles;
   if(bruteforce_map(titleIdPath, klicensee, header, unicv, pageMap, emptyFiles, unicv->isUnicv()) < 0)
      return -1;

   if(decrypt_files(titleIdPath, destTitleIdPath, klicensee, header, files, dirs, unicv, pageMap, emptyFiles) < 0)
      return -1;

   return 0;
}

int main(int argc, char* argv[])
{
   PsvPfsParserConfig cfg;

   if(parse_options(argc, argv, cfg) < 0)
      return -1;

   try
   {
      execute(cfg);
   }
   catch(std::exception& e)
   {
      std::cout << "Error: " << e.what() << std::endl;
   }

   return 0;
}

