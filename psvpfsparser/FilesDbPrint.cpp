#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <stdint.h>
#include <algorithm>
#include <map>
#include <iomanip>

#include "FilesDbParser.h"

void printBlocks(const std::vector<sce_ng_pfs_block_t>& root)
{
   for(size_t i = 0; i < root.size(); i++)
   {
      for(size_t j = 0; j < root[i].header.nFiles; j++)
      {
         std::cout << "-------------------------" << std::endl;
         std::cout << "name: " << std::endl;
         std::cout << std::dec << "index: " << root[i].files[j].index << std::endl;
         std::cout << std::dec << "name: " << std::string((const char*)root[i].files[j].fileName) << std::endl;
         
         std::cout << "info: " << std::endl;
         std::cout << std::dec << "index: " << root[i].infos[j].idx << std::endl;
         std::cout << std::hex << "size: " << root[i].infos[j].size << std::endl;
         std::cout << std::hex << "type: " << root[i].infos[j].type << std::endl;
         
         std::cout << std::hex << "unk1: " << root[i].infos[j].padding0 << std::endl;
         std::cout << std::hex << "unk2: " << root[i].infos[j].padding1 << std::endl;
      }
   }
}

void printHash(const sce_ng_pfs_hash_t& hash)
{
   for(size_t k = 0; k < sizeof(sce_ng_pfs_hash_t); k++)
   {
      std::cout << std::hex << std::setw(2) << std::setfill('0') << (int32_t)hash.data[k];
   }
   std::cout << std::endl;
}

void printHashes(const std::vector<sce_ng_pfs_block_t>& blocks)
{
   for(size_t i = 0; i < blocks.size(); i++)
   {
      std::cout << "---------------------" << std::endl;

      std::cout << std::dec << blocks[i].header.nFiles << std::endl;

      for(size_t j = 0; j < blocks[i].hashes.size(); j++)
      {
         printHash(blocks[i].hashes[j]);
      }
   }
}

/*
bool operator < (const sce_ng_pfs_file_info_t& fi1, const sce_ng_pfs_file_info_t& fi2)
{
   return fi1.idx < fi2.idx;
}

void constructIndexLists(const std::vector<sce_ng_pfs_block_t>& blocks)
{
   std::vector<std::pair<uint32_t, std::string> > files;

   for(std::vector<sce_ng_pfs_block_t>::const_iterator it = blocks.begin(); it != blocks.end(); ++it)
   {
      for(std::vector<sce_ng_pfs_file_header_t>::const_iterator fit = it->files.begin(); fit != it->files.end(); ++fit)
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

   for(std::vector<sce_ng_pfs_block_t>::const_iterator it = blocks.begin(); it != blocks.end(); ++it)
   {
      for(std::vector<sce_ng_pfs_file_info_t>::const_iterator fit = it->infos.begin(); fit != it->infos.end(); ++ fit)
      {
         infos.push_back(std::make_pair(fit->idx, *fit));
      }
   }

   std::sort(infos.begin(), infos.end());
}
*/

void debug_stuff()
{
   /*
   std::vector<uint32_t> sizes;
   for(std::vector<file_t>::const_iterator it = filesResult.begin(); it != filesResult.end(); ++it)
      sizes.push_back(it->block.info.size);
   std::sort(sizes.begin(), sizes.end());

   std::cout << "------------" << std::endl;

   for(std::vector<uint32_t>::const_iterator it = sizes.begin(); it != sizes.end(); ++it)
      std::cout << std::dec << (*it) << std::endl;
   */
}