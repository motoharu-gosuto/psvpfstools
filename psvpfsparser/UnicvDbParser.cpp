#include "UnicvDbParser.h"

#include <string>
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <iomanip>

#include <boost/filesystem.hpp>
#include <boost/range/iterator_range.hpp>

#include "UnicvDbTypes.h"

UnicvDbParser::UnicvDbParser(boost::filesystem::path titleIdPath)
   : m_titleIdPath(titleIdPath)
{
}

int UnicvDbParser::parse()
{
   if(!boost::filesystem::exists(m_titleIdPath))
   {
      std::cout << "Root directory does not exist" << std::endl;
      return -1;
   }

   boost::filesystem::path root(m_titleIdPath);

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
         std::cout << "parsing  icv.db..." << std::endl;

         m_fdb = std::make_shared<sce_icvdb_t>();
         if(!m_fdb->read(filepath2))
            return -1;

         return 0;
      }
   }
   else
   {
      std::cout << "parsing  unicv.db..." << std::endl;

      m_fdb = std::make_shared<sce_irodb_t>();
      if(!m_fdb->read(filepath))
         return -1;

      return 0;
   }
}

const std::shared_ptr<sce_idb_base_t>& UnicvDbParser::get_idatabase() const
{
   return m_fdb;
}