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

   //parse_unicv();

   parseAndFlattenFilesDb(titleId);

	return 0;
}

