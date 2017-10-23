#include "UnicvDbPrint.h"

#include <string>
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <iomanip>

#include <boost/filesystem.hpp>

void printVector(const uint8_t* data, size_t len)
{
   for(size_t i = 0; i < len; i++)
      std::cout << std::hex << std::setw(2) << std::setfill('0') << (int32_t)(data[i]);
   std::cout << std::endl;
}

void printVector(const std::vector<uint8_t>& data)
{
   for(std::vector<uint8_t>::const_iterator it = data.begin(); it != data.end(); ++it)
      std::cout << std::hex << std::setw(2) << std::setfill('0') << (int32_t)(*it);
   std::cout << std::endl;
}

void printUnicvDb(const files_db_t& fdb)
{
   /*
   std::cout << DB_MAGIC_WORD << std::endl;
   std::cout << "block size: " << std::hex << std::setw(8) << std::setfill('0') << fdb.dbHeader.blockSize << std::endl;
   std::cout << "data size: " << std::hex << std::setw(8) << std::setfill('0') << fdb.dbHeader.dataSize << std::endl;
   */

   std::cout << "table entries: " << std::dec << fdb.tables.size() << std::endl;

   uint32_t isEmpty = 0;

   std::vector<uint32_t> sizes;

   for(std::vector<files_ft_t>::const_iterator fit = fdb.tables.begin(); fit != fdb.tables.end(); ++fit)
   {
      if(fit->ftHeader.nSectors == 0)
         isEmpty++;

      /*
      std::cout << FT_MAGIC_WORD << std::endl;
      std::cout << "block size: " << std::hex << std::setw(8) << std::setfill('0') << fit->ftHeader.blockSize << std::endl;
      std::cout << "max n chunks: " << std::hex << std::setw(8) << std::setfill('0') << fit->ftHeader.maxNSectors << std::endl;
      */
      std::cout << "n chunks: " << std::hex << std::setw(8) << std::setfill('0') << fit->ftHeader.nSectors << std::endl;
      
      
      printVector(fit->ftHeader.data1, 20);
      printVector(fit->ftHeader.base_key, 20);

      /*
      for(std::vector<files_dt_t>::const_iterator dit = fit->blocks.begin(); dit != fit->blocks.end(); ++dit)
      {
         std::cout << "CHUNK_TABLE" << std::endl;
         std::cout << "payload size" << std::hex << std::setw(8) << std::setfill('0') << dit->dtHeader.payloadSize << std::endl;
         std::cout << "chunk size: " << std::hex << std::setw(8) << std::setfill('0') << dit->dtHeader.chunkSize << std::endl;
         std::cout << "n chunks: " << std::hex << std::setw(8) << std::setfill('0') << dit->dtHeader.nSectors << std::endl;
         
         for(std::vector<std::vector<uint8_t> >::const_iterator cit = dit->chunks.begin(); cit != dit->chunks.end(); ++cit)
            printVector(*cit);
      }
      */

      //sizes.push_back(fit->ftHeader.nSectors);
   }

   std::cout << "empty entries: " << std::dec << isEmpty << std::endl;

   /*
   //debug stuff
   std::sort(sizes.begin(), sizes.end());

   std::cout << "------------" << std::endl;

   for(std::vector<uint32_t>::const_iterator it = sizes.begin(); it != sizes.end(); ++it)
      std::cout << std::dec << (*it) << std::endl;
   */
}