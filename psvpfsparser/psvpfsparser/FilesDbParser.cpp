#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <stdint.h>
#include <algorithm>
#include <map>
#include <iomanip>
#include <set>

#include <boost/filesystem.hpp>
#include <boost/range/adaptor/reversed.hpp>
#include <boost/algorithm/string/predicate.hpp>

#include "FilesDbParser.h"

#include "Utils.h"

bool parseFilesDb(std::ifstream& inputStream, sce_ng_pfs_header_t& header, std::vector<sce_ng_pfs_block_t>& blocks)
{
   inputStream.read((char*)&header, sizeof(sce_ng_pfs_header_t));

   if(std::string((char*)header.magic, 8) != MAGIC_WORD)
   {
      std::cout << "Magic word is incorrect" << std::endl;
      return false;
   }

   //calculate tail size
   int64_t chunksBeginPos = inputStream.tellg();
   inputStream.seekg(0, std::ios_base::end);
   int64_t cunksEndPos = inputStream.tellg();
   int64_t dataSize = cunksEndPos - chunksBeginPos;

   //confirm tail size
   if(dataSize != header.tailSize)
   {
      std::cout << "Unexpected tail size" << std::endl;
      return false;
   }

   //check block size
   if(header.blockSize != EXPECTED_BLOCK_SIZE)
   {
      std::cout << "Invalid block size" << std::endl;
      return false;
   }

   //check padding
   if(!isZeroVector(header.padding + 0, header.padding + sizeof(header.padding)))
   {
      std::cout << "Unexpected data instead of padding" << std::endl;
      return false;
   }

   //seek back to the beginning of tail
   inputStream.seekg(chunksBeginPos, std::ios_base::beg);

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
         std::cout << "Unexpected type" << std::endl;
         return false;
      }

      if(block.header.padding != 0)
      {
         std::cout << "Unexpected padding" << std::endl;
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
            std::cout << "Unexpected padding" << std::endl;
            return false;
         }

         if(fi.padding1 != 0)
         {
            std::cout << "Unexpected unk1" << std::endl;
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
         std::cout << "Block overlay" << std::endl;
         return false;
      }
   }

   return true;
}

//build child index -> parent index relationship map
bool constructDirmatrix(const std::vector<sce_ng_pfs_block_t>& blocks, std::map<uint32_t, uint32_t>& dirMatrix)
{   
   for(auto& block : blocks)
   {
      for(uint32_t i = 0; i < block.header.nFiles; i++)
      {
         if(block.infos[i].type != directory)
            continue;

         uint32_t child = block.infos[i].idx;
         uint32_t parent = block.files[i].index;

         std::string fileName = std::string((const char*)block.files[i].fileName);

         if(block.infos[i].size != 0)
         {
            std::cout << "Directory " << fileName << " size is invalid" << std::endl;
            return false;
         }

         if(child == INVALID_FILE_INDEX)
         {
            std::cout << "Directory " << fileName << " index is invalid" << std::endl;
            return false;
         }

         if(dirMatrix.find(child) != dirMatrix.end())
         {
            std::cout << "Directory " << fileName << " index " << child << " is not unique" << std::endl;
            return false;
         }

         dirMatrix.insert(std::make_pair(child, parent));
      }
   }

   return true;
}

//build child index -> parent index relationship map
bool constructFileMatrix(const std::vector<sce_ng_pfs_block_t>& blocks, std::map<uint32_t, uint32_t>& fileMatrix)
{
   for(auto& block : blocks)
   {
      for(uint32_t i = 0; i < block.header.nFiles; i++)
      {
         if(block.infos[i].type == directory)
            continue;

         uint32_t child = block.infos[i].idx;
         uint32_t parent = block.files[i].index;

         std::string fileName = std::string((const char*)block.files[i].fileName);

         if(block.infos[i].size == 0)
         {   
            if(block.infos[i].type == unexisting)
            {
               std::cout << "[EMPTY] File " << fileName << " index " << child << std::endl;
               continue; // can not add unexisting files - they will conflict by index in the fileMatrix!
            }
            else
            {
               std::cout << "[EMPTY] File " << fileName << " index " << child << " has invalid type" << std::endl;
               return false;
            }
         }

         if(child == INVALID_FILE_INDEX)
         {
            std::cout << "Directory " << fileName << " index is invalid" << std::endl;
            return false;
         }

         if(fileMatrix.find(child) != fileMatrix.end())
         {
            std::cout << "File " << fileName << " index " << child << " is not unique" << std::endl;
            return false;
         }

         fileMatrix.insert(std::make_pair(child, parent));
      }
   }

   return true;
}

//convert list of blocks to list of files
//assign global index to files
void flattenBlocks(const std::vector<sce_ng_pfs_block_t>& blocks, std::vector<sce_ng_pfs_flat_block_t>& flatBlocks)
{
   int global_index = 0;

   for(auto& block : blocks)
   {
      for(uint32_t i = 0; i < block.header.nFiles; i++)
      {
         //have to skip unexisting files
         if(block.infos[i].size == 0 && block.infos[i].type == unexisting)
            continue;

         flatBlocks.push_back(sce_ng_pfs_flat_block_t());
         sce_ng_pfs_flat_block_t& fb = flatBlocks.back();

         fb.header = block.header;
         fb.file = block.files[i];
         fb.info = block.infos[i];
         fb.hash = block.hashes[i];

         fb.global_index = global_index++;
      }
   }
}

//find directory flat block by index
const std::vector<sce_ng_pfs_flat_block_t>::const_iterator findFlatBlockDir(const std::vector<sce_ng_pfs_flat_block_t>& flatBlocks, uint32_t index)
{
   size_t i = 0;
   for(auto& block : flatBlocks)
   {
      if(block.info.idx == index && block.info.type == directory)
         return flatBlocks.begin() + i;
      i++;
   }
   return flatBlocks.end();
}

//find file flat block by index
const std::vector<sce_ng_pfs_flat_block_t>::const_iterator findFlatBlockFile(const std::vector<sce_ng_pfs_flat_block_t>& flatBlocks, uint32_t index)
{
   size_t i = 0;
   for(auto& block : flatBlocks)
   {
      if(block.info.idx == index && block.info.type != directory)
         return flatBlocks.begin() + i;
      i++;
   }
   return flatBlocks.end();
}

//convert list of flat blocks to list of file paths
bool constructFilePaths(boost::filesystem::path rootPath, std::map<uint32_t, uint32_t>& dirMatrix, const std::map<uint32_t, uint32_t>& fileMatrix, const std::vector<sce_ng_pfs_flat_block_t>& flatBlocks, std::vector<sce_ng_pfs_file_t>& filesResult)
{
   for(auto& file_entry : fileMatrix)
   {
      //start searching from file up to root
      uint32_t childIndex = file_entry.first;
      uint32_t parentIndex = file_entry.second;

      std::vector<uint32_t> indexes;

      //search till the root - get all indexes for the path
      while(parentIndex != 0)
      {
         auto directory =  dirMatrix.find(parentIndex);
         if(directory == dirMatrix.end())
         {
            std::cout << "Missing parent directory index " << parentIndex  << std::endl;
            return false;
         }
         
         indexes.push_back(directory->first); //child - directory that was found
         parentIndex = directory->second; //parent - specify next directory to search
      }

      //find file flat block
      auto fileFlatBlock = findFlatBlockFile(flatBlocks, childIndex);
      if(fileFlatBlock == flatBlocks.end())
      {
         std::cout << "Missing file with index" << childIndex << std::endl;
         return false;
      }

      //find directory flat blocks and get directory names
      std::vector<std::string> dirNames;
      std::vector<sce_ng_pfs_flat_block_t> dirFlatBlocks;

      for(auto& dirIndex : indexes)
      {
         auto dirFlatBlock = findFlatBlockDir(flatBlocks, dirIndex);
         if(dirFlatBlock == flatBlocks.end())
         {
            std::cout << "Missing parent directory index " << dirIndex  << std::endl;
            return false;
         }

         dirFlatBlocks.push_back(*dirFlatBlock);
         dirNames.push_back(std::string((const char*)dirFlatBlock->file.fileName));
      }

      //get file name
      std::string fileName((const char*)fileFlatBlock->file.fileName);

      //construct full path
      boost::filesystem::path path = rootPath;
      for(auto& dname : boost::adaptors::reverse(dirNames))
      {
         path /= dname;
      }
      path /= fileName;

      filesResult.push_back(sce_ng_pfs_file_t());
      sce_ng_pfs_file_t& ft = filesResult.back();
      ft.path = path;
      ft.file = *fileFlatBlock;
      ft.dirs = dirFlatBlocks;
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

//checks that files exist
//checks that file size is correct
bool validateFilepaths(std::vector<sce_ng_pfs_file_t> files)
{
   for(auto& file : files)
   {
      //std::cout << file.path << " : ";
      
      if(!boost::filesystem::exists(file.path))
      {
         std::cout << "File " << file.path.generic_string() << " does not exist" << std::endl;
         return false;
      }
      
      uint64_t size = boost::filesystem::file_size(file.path);
      if(size != file.file.info.size)
      {
         std::cout << "File " << file.path.generic_string() << " size incorrect" << std::endl;
         return false;
      }

      //std::cout << fileTypeToString(file.file.info.type)<< " : ";

      //std::cout << std::hex << std::setw(8) << std::setfill('0') << file.file.info.size << std::endl;
   }
   return true;
}

//get files recoursively
void getFileList(boost::filesystem::path path, std::set<std::string>& files, std::set<std::string>& directories)
{
   if (!path.empty())
   {
      boost::filesystem::path apk_path(path);
      boost::filesystem::recursive_directory_iterator end;

      for (boost::filesystem::recursive_directory_iterator i(apk_path); i != end; ++i)
      {
         const boost::filesystem::path cp = (*i);

         //skip paths that are not included in files.db
         if(boost::starts_with(cp, (path / boost::filesystem::path("sce_pfs"))))
            continue;

         if(boost::starts_with(cp, (path / boost::filesystem::path("sce_sys") / boost::filesystem::path("package"))))
            continue;

         //add file or directory
         if(boost::filesystem::is_directory(cp))
            directories.insert(cp.string());
         else
            files.insert(cp.string());
      }
   }
}

int match_file_lists(std::vector<sce_ng_pfs_file_t>& filesResult, std::set<std::string> files)
{
   std::set<std::string> fileResultPaths;

   for(auto& f :  filesResult)
      fileResultPaths.insert(f.path.string());

   std::cout << "Files not found in files.db :" << std::endl;

   for(auto& p : files)
   {
      if(fileResultPaths.find(p) == fileResultPaths.end())
         std::cout << p << std::endl;
   }

   std::cout << "Files not found in filesystem :" << std::endl;

   for(auto& p : fileResultPaths)
   {
      if(files.find(p) == files.end())
         std::cout << p << std::endl;
   }

   return 0;
}

//parses files.db and flattens it into file list
int parseFilesDb(std::string title_id_path, std::vector<sce_ng_pfs_file_t>& filesResult)
{
   boost::filesystem::path root(title_id_path);

   boost::filesystem::path filepath = root / "sce_pfs\\files.db";
   std::ifstream inputStream(filepath.generic_string().c_str(), std::ios::in | std::ios::binary);

   //parse data into raw structures
   sce_ng_pfs_header_t header;
   std::vector<sce_ng_pfs_block_t> blocks;
   if(!parseFilesDb(inputStream, header, blocks))
      return -1;

   //build child index -> parent index relationship map
   std::map<uint32_t, uint32_t> dirMatrix;
   if(!constructDirmatrix(blocks, dirMatrix))
      return -1;

   //build child index -> parent index relationship map
   std::map<uint32_t, uint32_t> fileMatrix;
   if(!constructFileMatrix(blocks, fileMatrix))
      return -1;
   
   //convert list of blocks to list of files
   std::vector<sce_ng_pfs_flat_block_t> flatBlocks;
   flattenBlocks(blocks, flatBlocks);

   //convert flat blocks to file paths
   if(!constructFilePaths(root, dirMatrix, fileMatrix, flatBlocks, filesResult))
      return -1;

   //validate result files (path, size)
   if(!validateFilepaths(filesResult))
      return -1;

   //match on existing files in filesystem
   std::set<std::string> files;
   std::set<std::string> directories;
   getFileList(root, files, directories);

   match_file_lists(filesResult, files);

   //final check of sizes
   size_t expectedSize = files.size() + directories.size();
   if(expectedSize != flatBlocks.size())
   {
      std::cout << "Mismatch in number of files + directories agains number of flat blocks" << std::endl;
      return -1;
   }

	return 0;
}