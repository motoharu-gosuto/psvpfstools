#include <string>
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <iomanip>

#include <boost/filesystem.hpp>

#include "UnicvDbParser.h"
#include "UnicvDbPrint.h"

int main(int argc, char* argv[])
{
	if(argc <2)
   {
      std::cout << "psvpfsparser <TitleID path>" << std::endl;
      return 0;
   }

   boost::filesystem::path filepath = boost::filesystem::path(argv[1]) / "sce_pfs\\unicv.db";
   
   files_db_t fdb;
   parseUnicvDb(filepath, fdb);
   
   //printUnicvDb(fdb);

	return 0;
}

