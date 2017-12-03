#include "UnicvDbParser.h"

#include <string>
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <iomanip>

#include <boost/filesystem.hpp>
#include <boost/range/iterator_range.hpp>

#include "UnicvDbTypes.h"

int parseUnicvDb(boost::filesystem::path titleIdPath, std::shared_ptr<scei_db_base_t>& fdb)
{
   std::cout << "parsing  unicv.db..." << std::endl;

   boost::filesystem::path root(titleIdPath);

   boost::filesystem::path filepath = root / "sce_pfs" / "unicv.db";

   if(!boost::filesystem::exists(filepath))
   {
      boost::filesystem::path filepath2 = root / "sce_pfs" / "icv.db";
      if(!boost::filesystem::exists(filepath2) || !boost::filesystem::is_directory(filepath2))
      {
         std::cout << "failed to find unicv.db file or icv.db folder" << std::endl;
         return -1;
      }
      else
      {
         fdb = std::make_shared<scei_icv_t>();
         if(!fdb->read(filepath2))
            return -1;

         return 0;
      }
   }
   else
   {
      fdb = std::make_shared<scei_rodb_t>();
      if(!fdb->read(filepath))
         return -1;

      return 0;
   }
}
