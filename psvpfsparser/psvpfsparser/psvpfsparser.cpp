#include <string>
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <iomanip>

#include <boost/filesystem.hpp>

#include "UnicvDbParser.h"
#include "FilesDbParser.h"

int match_by_size(const scei_rodb_t& unicv, const std::vector<sce_ng_pfs_file_t>& files)
{
   std::vector<std::pair<uint32_t, scei_ftbl_t>> unicv_files_by_block_size;
   std::vector<std::pair<uint32_t, sce_ng_pfs_file_t>> filesdb_files_by_block_size;
   
   for(auto& f : files)
   {
      if(f.file.global_index >= unicv.tables.size())
      {
         std::cout << "Index out of range" << std::endl;
         return -1;
      }

      const scei_ftbl_t& tbl = unicv.tables.at(f.file.global_index);
      uint32_t nSectors = tbl.ftHeader.nSectors;

      uint32_t nBlocks = f.file.info.size / tbl.ftHeader.fileDbSectorSize;
      uint32_t nTail = f.file.info.size % tbl.ftHeader.fileDbSectorSize;
      nTail = nTail > 0 ? 1 : 0;
      nBlocks = nBlocks + nTail;

      unicv_files_by_block_size.push_back(std::make_pair(nSectors, tbl));
      filesdb_files_by_block_size.push_back(std::make_pair(nBlocks, f));

      std::sort(unicv_files_by_block_size.begin(), unicv_files_by_block_size.end(), 
         [](const std::pair<uint32_t, scei_ftbl_t> &left, const std::pair<uint32_t, scei_ftbl_t> &right) {
            return left.first > right.first;
      });

      std::sort(filesdb_files_by_block_size.begin(), filesdb_files_by_block_size.end(), 
         [](const std::pair<uint32_t, sce_ng_pfs_file_t> &left, const std::pair<uint32_t, sce_ng_pfs_file_t> &right) {
            return left.first > right.first;
      });
   }

   return 0;
}

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

   match_by_size(unicv, files);

	return 0;
}

