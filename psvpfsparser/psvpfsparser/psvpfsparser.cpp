#include <string>
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <iomanip>

#include <boost/filesystem.hpp>

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

   std::string titleId(argv[1]);

   std::string destTitleId(argv[2]);

   unsigned char klicensee[0x10] = {0};
   if(string_to_byte_array(std::string(argv[3]), 0x10, klicensee) < 0)
   {
      std::cout << "Failed to parse klicensee" << std::endl;
      return -1;
   }

   set_F00D_url(std::string(argv[4]));

   sce_ng_pfs_header_t header;
   std::vector<sce_ng_pfs_file_t> files;
   parseFilesDb(klicensee, titleId, header, files);

   scei_rodb_t unicv;
   parseUnicvDb(titleId, unicv);

   std::map<uint32_t, std::string> pageMap;
   bruteforce_map(titleId, klicensee, header, unicv, pageMap);

   decrypt_files(titleId, destTitleId, klicensee, header, files, unicv, pageMap);

	return 0;
}

