#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <stdint.h>
#include <algorithm>
#include <map>
#include <iomanip>

#include <boost/filesystem.hpp>

#include "FilesDbParser.h"

#include "Utils.h"

using namespace std;

bool parseFilesDb(ifstream& inputStream, sce_ng_pfs_header_t& header, vector<sce_ng_pfs_block_t>& blocks)
{
   inputStream.read((char*)&header, sizeof(sce_ng_pfs_header_t));

   if(std::string((char*)header.magic, 8) != MAGIC_WORD)
   {
      cout << "Magic word is incorrect" << endl;
      return false;
   }

   //calculate tail size
   int64_t chunksBeginPos = inputStream.tellg();
   inputStream.seekg(0, ios_base::end);
   int64_t cunksEndPos = inputStream.tellg();
   int64_t dataSize = cunksEndPos - chunksBeginPos;

   //confirm tail size
   if(dataSize != header.tailSize)
   {
      cout << "Unexpected tail size" << endl;
      return false;
   }

   //check block size
   if(header.blockSize != EXPECTED_BLOCK_SIZE)
   {
      cout << "Invalid block size" << endl;
      return false;
   }

   //check padding
   if(!isZeroVector(header.padding + 0, header.padding + sizeof(header.padding)))
   {
      std::cout << "Unexpected data instead of padding" << std::endl;
      return false;
   }

   //seek back to the beginning of tail
   inputStream.seekg(chunksBeginPos, ios_base::beg);

   while(true)
   {
      int64_t currentBlockPos = inputStream.tellg();

      if(currentBlockPos >= cunksEndPos)
         break;

      blocks.push_back(sce_ng_pfs_block_t());
      sce_ng_pfs_block_t& block = blocks.back();

      inputStream.read((char*)&block.header, sizeof(sce_ng_pfs_block_header_t));

      if(block.header.type != sce_ng_pfs_block_types::regular && 
         block.header.type != sce_ng_pfs_block_types::unknown_block_type)
      {
         cout << "Unexpected type" << endl;
         return false;
      }

      if(block.header.padding != 0)
      {
         cout << "Unexpected padding" << endl;
         return false;
      }

      //read file records
      for(uint32_t i = 0; i < block.header.nFiles; i++)
      {
         block.files.push_back(sce_ng_pfs_file_header_t());
         sce_ng_pfs_file_header_t& fh = block.files.back();
         inputStream.read((char*)&fh, sizeof(sce_ng_pfs_file_header_t));
      }

      //skip / test / read unused data
      uint32_t nUnused = MAX_FILES_IN_BLOCK - block.header.nFiles;
      uint32_t nUnusedSize1 = nUnused * sizeof(sce_ng_pfs_file_header_t);
      if(nUnusedSize1 > 0)
      {
         std::vector<uint8_t> unusedData1(nUnusedSize1);
         inputStream.read((char*)unusedData1.data(), nUnusedSize1);

         if(!isZeroVector(unusedData1))
         {
            std::cout << "Unexpected data instead of padding" << std::endl;
            return false;
         }
      }
      
      //skip will be faster
      //inputStream.seekg(nUnusedSize1, ios_base::cur);

      //read file information records
      //looks like there are 9 + 1 records in total
      //some of the records may contain INVALID_FILE_INDEX as idx
      for(uint32_t i = 0; i < 10; i++)
      {
         block.infos.push_back(sce_ng_pfs_file_info_t());
         sce_ng_pfs_file_info_t& fi = block.infos.back();
         inputStream.read((char*)&fi, sizeof(sce_ng_pfs_file_info_t));

         //check file type
         if(fi.type != unexisting && fi.type != normal_file && fi.type != directory && fi.type != unencrypted_system_file && fi.type != encrypted_system_file)
         {
            std::cout << "Unexpected file type" << std::endl;
            return false;
         }

         if(fi.padding0 != 0)
         {
            cout << "Unexpected padding" << endl;
            return false;
         }

         if(fi.padding1 != 0)
         {
            cout << "Unexpected unk1" << endl;
            return false;
         }
      }

      //read hash table ?
      int64_t currentBlockPos2 = inputStream.tellg();

      for(int32_t i = 0; i < 10; i++)
      {
         block.hashes.push_back(sce_ng_pfs_hash_t());
         sce_ng_pfs_hash_t& h = block.hashes.back();

         inputStream.read((char*)&h.data, sizeof(sce_ng_pfs_hash_t));
      }

      //validate next position - check that read operations we not out of bounds of current block
      int64_t nextBlockPos = currentBlockPos + header.blockSize;
      if((int64_t)inputStream.tellg() != nextBlockPos)
      {
         cout << "Block overlay" << endl;
         return false;
      }
   }

   return true;
}

bool operator < (const sce_ng_pfs_file_info_t& fi1, const sce_ng_pfs_file_info_t& fi2)
{
   return fi1.idx < fi2.idx;
}

void constructIndexLists(const vector<sce_ng_pfs_block_t>& blocks)
{
   std::vector<std::pair<uint32_t, std::string> > files;

   for(vector<sce_ng_pfs_block_t>::const_iterator it = blocks.begin(); it != blocks.end(); ++it)
   {
      for(vector<sce_ng_pfs_file_header_t>::const_iterator fit = it->files.begin(); fit != it->files.end(); ++fit)
      {
         files.push_back(std::make_pair(fit->index, std::string((const char*)fit->fileName)));
      }
   }

   std::sort(files.begin(), files.end());

   for(std::vector<std::pair<uint32_t, std::string> >::const_iterator it = files.begin(); it != files.end(); ++it)
   {
      std::cout << it->first << " " << it->second << std::endl;
   }

   std::vector<std::pair<uint32_t, sce_ng_pfs_file_info_t> > infos;

   for(vector<sce_ng_pfs_block_t>::const_iterator it = blocks.begin(); it != blocks.end(); ++it)
   {
      for(vector<sce_ng_pfs_file_info_t>::const_iterator fit = it->infos.begin(); fit != it->infos.end(); ++ fit)
      {
         infos.push_back(std::make_pair(fit->idx, *fit));
      }
   }

   std::sort(infos.begin(), infos.end());
}

bool constructDirmatrix(const vector<sce_ng_pfs_block_t>& blocks, std::map<uint32_t, uint32_t>& dirMatrix)
{
   //child -> parent matrix

   for(vector<sce_ng_pfs_block_t>::const_iterator it = blocks.begin(); it != blocks.end(); ++it)
   {
      for(uint32_t i = 0; i < it->header.nFiles; i++)
      {
         if(it->infos[i].type != directory)
            continue;

         uint32_t child = it->infos[i].idx;
         uint32_t parent = it->files[i].index;

         if(dirMatrix.find(child) != dirMatrix.end())
         {
            std::string fileName = std::string((const char*)it->files[i].fileName);
            cout << "Directory " << fileName << " index " << child << " is not unique" << endl;
            return false;
         }

         std::pair<uint32_t, uint32_t> key = std::make_pair(child, parent);
         dirMatrix.insert(key);
      }
   }

   return true;
}

bool constructFileMatrix(const vector<sce_ng_pfs_block_t>& blocks, std::map<uint32_t, uint32_t>& fileMatrix)
{
   //child -> parent matrix

   for(vector<sce_ng_pfs_block_t>::const_iterator it = blocks.begin(); it != blocks.end(); ++it)
   {
      for(uint32_t i = 0; i < it->header.nFiles; i++)
      {
         if(it->infos[i].type == directory)
            continue;

         uint32_t child = it->infos[i].idx;
         uint32_t parent = it->files[i].index;

         std::string fileName = std::string((const char*)it->files[i].fileName);

         if(it->infos[i].size == 0 && it->infos[i].type == unexisting)
         {   
            cout << "[EMPTY] File " << fileName << " index " << child << endl;
            continue;
         }

         if(fileMatrix.find(child) != fileMatrix.end())
         {
            cout << "File " << fileName << " index " << child << " is not unique" << endl;
            return false;
         }

         std::pair<uint32_t, uint32_t> key = std::make_pair(child, parent);
         fileMatrix.insert(key);
      }
   }

   return true;
}

void flattenBlocks(const vector<sce_ng_pfs_block_t>& blocks, vector<sce_ng_pfs_flat_block_t>& flatBlocks)
{
   for(vector<sce_ng_pfs_block_t>::const_iterator it = blocks.begin(); it != blocks.end(); ++it)
   {
      for(uint32_t i = 0; i < it->header.nFiles; i++)
      {
         if(it->infos[i].size == 0 && it->infos[i].type == unexisting)
            continue;

         flatBlocks.push_back(sce_ng_pfs_flat_block_t());
         sce_ng_pfs_flat_block_t& fb = flatBlocks.back();

         fb.header = it->header;
         fb.file = it->files[i];
         fb.info = it->infos[i];
         fb.hash = it->hashes[i];
      }
   }
}

const vector<sce_ng_pfs_flat_block_t>::const_iterator findFlatBlockDir(const vector<sce_ng_pfs_flat_block_t>& flatBlocks, uint32_t index)
{
   size_t i = 0;

   for(vector<sce_ng_pfs_flat_block_t>::const_iterator it = flatBlocks.begin(); it != flatBlocks.end(); ++it, i++)
   {
      if(it->info.idx == index && it->info.type == directory)
         return flatBlocks.begin() + i;
   }
   
   return flatBlocks.end();
}

const vector<sce_ng_pfs_flat_block_t>::const_iterator findFlatBlockFile(const vector<sce_ng_pfs_flat_block_t>& flatBlocks, uint32_t index)
{
   size_t i = 0;

   for(vector<sce_ng_pfs_flat_block_t>::const_iterator it = flatBlocks.begin(); it != flatBlocks.end(); ++it, i++)
   {
      if(it->info.idx == index && it->info.type != directory)
         return flatBlocks.begin() + i;
   }
   
   return flatBlocks.end();
}

bool constructFilePaths(std::string rootPath, std::map<uint32_t, uint32_t>& dirMatrix, const std::map<uint32_t, uint32_t>& fileMatrix, const vector<sce_ng_pfs_flat_block_t>& flatBlocks, std::vector<sce_ng_pfs_file_t>& filesResult)
{
   for(std::map<uint32_t, uint32_t>::const_iterator it = fileMatrix.begin(); it != fileMatrix.end(); ++it)
   {
      uint32_t child = it->first;
      uint32_t parent = it->second;

      std::vector<uint32_t> indexes;

      while(parent != 0)
      {
         std::map<uint32_t, uint32_t>::const_iterator dit =  dirMatrix.find(parent);
         if(dit == dirMatrix.end())
         {
            cout << "Missing parent directory index " << parent  << endl;
            return false;
         }
         
         indexes.push_back(dit->first);
         parent = dit->second;
      }

      vector<sce_ng_pfs_flat_block_t>::const_iterator fileBlockIt = findFlatBlockFile(flatBlocks, child);
      if(fileBlockIt == flatBlocks.end())
      {
         cout << "Missing file with index" << child << endl;
         return false;
      }

      std::string fileName((const char*)fileBlockIt->file.fileName);

      std::vector<std::string> dirNames;

      for(std::vector<uint32_t>::const_iterator indit = indexes.begin(); indit != indexes.end(); ++indit)
      {
         uint32_t idx = *indit;

         vector<sce_ng_pfs_flat_block_t>::const_iterator blockIt = findFlatBlockDir(flatBlocks, idx);
         if(blockIt == flatBlocks.end())
         {
            cout << "Missing parent directory index " << idx  << endl;
            return false;
         }

         dirNames.push_back(std::string((const char*)blockIt->file.fileName));
      }

      std::string path = "";
      for(std::vector<std::string>::const_reverse_iterator pit = dirNames.rbegin(); pit != dirNames.rend(); ++pit)
      {
         path = path + *pit + "/";
      }

      path = rootPath + path + fileName;

      filesResult.push_back(sce_ng_pfs_file_t());
      sce_ng_pfs_file_t& ft = filesResult.back();
      ft.path = path;
      ft.block = *fileBlockIt;
   }

   return true;
}

std::string fileTypeToString(sce_ng_pfs_file_types ft)
{
   switch(ft)
   {
   case unexisting:
      return "unexisting";
   case normal_file:
      return "normal_file";
   case directory:
      return "directory";
   case unencrypted_system_file:
      return "unencrypted_system_file";
   case encrypted_system_file:
      return "encrypted_system_file";
   default:
      return "unknown";
   }
}

int parseAndFlattenFilesDb(std::string title_id_path)
{
   boost::filesystem::path filepath = boost::filesystem::path(title_id_path) / "sce_pfs\\files.db";

   ifstream inputStream(filepath.generic_string().c_str(), ios::in | ios::binary);

   sce_ng_pfs_header_t header;
   vector<sce_ng_pfs_block_t> blocks;
   if(!parseFilesDb(inputStream, header, blocks))
      return -1;

   std::map<uint32_t, uint32_t> dirMatrix;
   if(!constructDirmatrix(blocks, dirMatrix))
      return -1;

   std::map<uint32_t, uint32_t> fileMatrix;
   if(!constructFileMatrix(blocks, fileMatrix))
      return -1;
   
   vector<sce_ng_pfs_flat_block_t> flatBlocks;
   flattenBlocks(blocks, flatBlocks);

   std::vector<sce_ng_pfs_file_t> filesResult;
   if(!constructFilePaths(boost::filesystem::path(title_id_path).generic_string() , dirMatrix, fileMatrix, flatBlocks, filesResult))
      return -1;

   for(std::vector<sce_ng_pfs_file_t>::const_iterator it = filesResult.begin(); it != filesResult.end(); ++it)
   {
      std::cout << it->path << endl;
      
      if(!boost::filesystem::exists(it->path))
      {
         cout << "File " << it->path.generic_string() << " does not exist" << endl;
         continue;
      }
      
      uint64_t size = boost::filesystem::file_size(it->path);
      if(size != it->block.info.size)
      {
         cout << "File " << it->path.generic_string() << " size incorrect" << endl;
         continue;
      }

      cout << fileTypeToString(it->block.info.type)<< endl;

      std::cout << std::hex << std::setw(8) << std::setfill('0') << it->block.info.size << std::endl;
   }

   //debug stuff
   /*
   std::vector<uint32_t> sizes;
   for(std::vector<file_t>::const_iterator it = filesResult.begin(); it != filesResult.end(); ++it)
      sizes.push_back(it->block.info.size);
   std::sort(sizes.begin(), sizes.end());

   std::cout << "------------" << std::endl;

   for(std::vector<uint32_t>::const_iterator it = sizes.begin(); it != sizes.end(); ++it)
      std::cout << std::dec << (*it) << std::endl;
   */

	return 0;
}