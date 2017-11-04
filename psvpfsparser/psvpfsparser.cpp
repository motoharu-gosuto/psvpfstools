#include <string>
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <iomanip>

#include <boost/filesystem.hpp>
#include <boost/algorithm/string.hpp>

#include "Utils.h"

#include "UnicvDbParser.h"
#include "FilesDbParser.h"
#include "PfsDecryptor.h"
#include "F00DKeyEncryptor.h"

int main(int argc, char* argv[])
{
	if(argc < 5)
   {
      std::cout << "psvpfsparser <TitleID path> <TitleID path dest> <klicensee> <F00D url>" << std::endl;
      return 0;
   }

   //trim slashes in source path
   std::string titleId(argv[1]);
   boost::filesystem::path titleIdPath(titleId);
   std::string titleIdGen = titleIdPath.generic_string();
   boost::algorithm::trim_right_if(titleIdGen, [](char c){return c == '/';});
   titleIdPath = boost::filesystem::path(titleIdGen);

   //trim slashes in dest path
   std::string destTitleId(argv[2]);
   boost::filesystem::path destTitleIdPath(destTitleId);
   std::string destTitleIdPathGen = destTitleIdPath.generic_string();
   boost::algorithm::trim_right_if(destTitleIdPathGen, [](char c){return c == '/';});
   destTitleIdPath = boost::filesystem::path(destTitleIdPathGen);

   unsigned char klicensee[0x10] = {0};
   if(string_to_byte_array(std::string(argv[3]), 0x10, klicensee) < 0)
   {
      std::cout << "Failed to parse klicensee" << std::endl;
      return -1;
   }

   set_F00D_url(std::string(argv[4]));

   if(!boost::filesystem::exists(titleIdPath))
   {
      std::cout << "Root directory does not exist" << std::endl;
      return -1;
   }

   sce_ng_pfs_header_t header;
   std::vector<sce_ng_pfs_file_t> files;
   if(parseFilesDb(klicensee, titleIdPath, header, files) < 0)
      return -1;

   scei_rodb_t unicv;
   if(parseUnicvDb(titleIdPath, unicv) < 0)
      return -1;

   std::map<uint32_t, std::string> pageMap;
   if(bruteforce_map(titleIdPath, klicensee, header, unicv, pageMap) < 0)
      return -1;

   if(decrypt_files(titleIdPath, destTitleIdPath, klicensee, header, files, unicv, pageMap) < 0)
      return -1;

	return 0;
}

