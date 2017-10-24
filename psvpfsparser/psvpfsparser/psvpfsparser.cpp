#include <string>
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <iomanip>

#include <boost/filesystem.hpp>

#include "UnicvDbParser.h"
#include "FilesDbParser.h"

int main(int argc, char* argv[])
{
	if(argc <2)
   {
      std::cout << "psvpfsparser <TitleID path>" << std::endl;
      return 0;
   }

   std::string titleId(argv[1]);

   scei_rodb_t unicv;
   parseUnicvDb(titleId, unicv);

   std::vector<sce_ng_pfs_file_t> files;
   parseFilesDb(titleId, files);

	return 0;
}

