#include "UnicvDbParser.h"

#include <string>
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <iomanip>

#include <boost/filesystem.hpp>

bool isZeroVector(std::vector<uint8_t> data)
{
   for(std::vector<uint8_t>::const_iterator it = data.begin(); it != data.end(); ++it)
   {
      if((*it) != 0)
         return false;
   }
   return true;
}

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

void debugPrint(const files_db_t& fdb)
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
      if(fit->ftHeader.nChunks == 0)
         isEmpty++;

      /*
      std::cout << FT_MAGIC_WORD << std::endl;
      std::cout << "block size: " << std::hex << std::setw(8) << std::setfill('0') << fit->ftHeader.blockSize << std::endl;
      std::cout << "max n chunks: " << std::hex << std::setw(8) << std::setfill('0') << fit->ftHeader.maxNChunks << std::endl;
      */
      std::cout << "n chunks: " << std::hex << std::setw(8) << std::setfill('0') << fit->ftHeader.nChunks << std::endl;
      
      
      printVector(fit->ftHeader.data1, 20);
      printVector(fit->ftHeader.data2, 20);

      /*
      for(std::vector<files_dt_t>::const_iterator dit = fit->blocks.begin(); dit != fit->blocks.end(); ++dit)
      {
         std::cout << "CHUNK_TABLE" << std::endl;
         std::cout << "payload size" << std::hex << std::setw(8) << std::setfill('0') << dit->dtHeader.payloadSize << std::endl;
         std::cout << "chunk size: " << std::hex << std::setw(8) << std::setfill('0') << dit->dtHeader.chunkSize << std::endl;
         std::cout << "n chunks: " << std::hex << std::setw(8) << std::setfill('0') << dit->dtHeader.nChunks << std::endl;
         
         for(std::vector<std::vector<uint8_t> >::const_iterator cit = dit->chunks.begin(); cit != dit->chunks.end(); ++cit)
            printVector(*cit);
      }
      */

      //sizes.push_back(fit->ftHeader.nChunks);
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

bool readDataChunkBlock(std::ifstream& inputStream, ft_header_t& ftHeader, uint32_t sizeCheck, files_dt_t& fdt)
{
   uint64_t cpo = inputStream.tellg();

   inputStream.read((char*)&fdt.dtHeader, sizeof(dt_header_t));

   //TODO:
   //just a temp check to see if there are any other sizes
   if(fdt.dtHeader.chunkSize != EXPECTED_CHUNK_SIZE)
   {
      std::cout << "Unexpected chunk size" << std::endl;
      return false;
   }

   //this check is usefull for validating file structure
   if(fdt.dtHeader.nChunks != sizeCheck)
   {
      std::cout << "unexpected number of chunks" << std::endl;
      return false;
   }

   for(uint32_t c = 0; c < fdt.dtHeader.nChunks; c++)
   {
      fdt.chunks.push_back(std::vector<uint8_t>());
      std::vector<uint8_t>& dte = fdt.chunks.back();
      dte.resize(fdt.dtHeader.chunkSize);
      inputStream.read((char*)dte.data(), fdt.dtHeader.chunkSize);
   }

   //skip padding - move to next record
   //can either use seekg or check if there is any other data - should be zeroes
   uint64_t cp = inputStream.tellg();
   int64_t tail = ftHeader.blockSize - (cp - cpo);

   //inputStream.seekg(tail, std::ios::cur);

   //TODO: this is a debug check - remove it
   std::vector<uint8_t> data(tail);
   inputStream.read((char*)data.data(), tail);

   if(!isZeroVector(data))
   {
      std::cout << "Unexpected data instead of padding" << std::endl;
      return false;
   }

   return true;
}

bool readDataBlock(std::ifstream& inputStream, uint64_t& i, files_ft_t& fft)
{
   inputStream.read((char*)&fft.ftHeader, sizeof(ft_header_t));

   //TODO:
   //for now it is just a simple check to see if there are any other block sizes
   if(fft.ftHeader.blockSize != EXPECTED_BLOCK_SIZE)
   {
      std::cout << "Unexpected block size" << std::endl;
      return false;
   }

   //check magic word
   if(std::string((const char*)fft.ftHeader.magic, 8) != FT_MAGIC_WORD)
   {
      std::cout << "Invalid magic word" << std::endl;
      return false;
   }

   //skip padding - move to next record
   //can either use seekg or check if there is any other data - should be zeroes
   uint64_t tail = fft.ftHeader.blockSize - sizeof(ft_header_t);
         
   //inputStream.seekg(tail, std::ios::cur);

   //TODO: this is a debug check - remove it
   std::vector<uint8_t> tailData(tail);
   inputStream.read((char*)tailData.data(), tail);

   if(!isZeroVector(tailData))
   {
      std::cout << "Unexpected data instead of padding" << std::endl;
      return false;
   }

   //check if there are any data blocks after current entry
   if(fft.ftHeader.nChunks == 0)
      return true;

   uint64_t cpo = inputStream.tellg();
   dt_header_t dtHeader;
   inputStream.read((char*)&dtHeader, sizeof(dt_header_t));
   inputStream.seekg(cpo, std::ios::beg);
      
   uint32_t dataAvailable = (fft.ftHeader.blockSize - sizeof(dt_header_t)) / dtHeader.chunkSize;
   dataAvailable = dataAvailable * dtHeader.chunkSize; // just rounding
   uint32_t dataReq = fft.ftHeader.nChunks * dtHeader.chunkSize;
         
   //if only single data block is required
   if(dataReq < dataAvailable)
   {
      fft.blocks.push_back(files_dt_t());
      files_dt_t& fdt = fft.blocks.back();

      if(!readDataChunkBlock(inputStream, fft.ftHeader, fft.ftHeader.nChunks, fdt))
         return false;
      i++;
      return true;
   }
   
   //if there are multiple data blocks required
   uint32_t nDataBlocks = dataReq / dataAvailable;
   uint32_t nDataTail = dataReq % dataAvailable;

   uint32_t nDataTailN = nDataTail / dtHeader.chunkSize;
   uint32_t nDataTailNTail = nDataTail % dtHeader.chunkSize;

   if(nDataTailNTail != 0)
   {
      std::cout << "Unexpected misalign" << std::endl;
      return -1;
   }

   for(uint32_t dbi = 0; dbi < nDataBlocks; dbi++)
   {
      fft.blocks.push_back(files_dt_t());
      files_dt_t& fdt = fft.blocks.back();

      if(!readDataChunkBlock(inputStream, fft.ftHeader, fft.ftHeader.maxNChunks, fdt))
         return false;
      i++;
   }

   if(nDataTailN > 0)
   {
      fft.blocks.push_back(files_dt_t());
      files_dt_t& fdt = fft.blocks.back();

      if(!readDataChunkBlock(inputStream, fft.ftHeader, nDataTailN, fdt))
         return false;
      i++;
   }

   return true;
}

bool parseFilesDb(boost::filesystem::path filepath, files_db_t& fdb)
{
   std::ifstream inputStream(filepath.generic_string().c_str(), std::ios::in | std::ios::binary);

   inputStream.read((char*)&fdb.dbHeader, sizeof(db_header_t));

   //check file size field
   uint64_t fileSize = boost::filesystem::file_size(filepath);
   if(fileSize != (fdb.dbHeader.dataSize + fdb.dbHeader.blockSize)) //do not forget to count header
   {
      std::cout << "Incorrect block size or data size" << std::endl;
      return false;
   }

   //check magic word
   if(std::string((const char*)fdb.dbHeader.magic, 8) != DB_MAGIC_WORD)
   {
      std::cout << "Invalid magic word" << std::endl;
      return false;
   }

   //TODO: debug check only for now to see if there are any other sizes
   if(fdb.dbHeader.blockSize != EXPECTED_BLOCK_SIZE)
   {
      std::cout << "Unexpected block size" << std::endl;
      return false;
   }

   inputStream.seekg(fdb.dbHeader.blockSize, std::ios::beg); //skip header

   //TODO:
   //I am not sure if this the right way to calculate number of blocks
   //it looks like each block has it is own size so technically
   //reading should be implemented in stream manner
   uint64_t nBlocks = fdb.dbHeader.dataSize / fdb.dbHeader.blockSize;
   uint64_t tailSize = fdb.dbHeader.dataSize % fdb.dbHeader.blockSize;

   //check tail size just in case
   if(tailSize > 0)
   {
      std::cout << "Block misalign" << std::endl;
      return false;
   }

   std::cout << "Total blocks: " << std::dec << nBlocks << std::endl;

   //read all blocks
   for(uint64_t i = 0; i < nBlocks; i++)
   {
      fdb.tables.push_back(files_ft_t());
      files_ft_t& fft = fdb.tables.back();

      if(!readDataBlock(inputStream, i, fft))
         return false;
   }

   uint64_t endp = inputStream.tellg();
   if(fileSize != endp)
   {
      std::cout << "Data misalign" << std::endl;
      return false;
   }

   return true;
}