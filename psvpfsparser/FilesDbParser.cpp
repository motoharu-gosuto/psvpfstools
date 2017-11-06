#include <fcntl.h>  
#include <stdlib.h>  
#include <stdio.h>  

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

#include "SecretGenerator.h"
#include "NodeIcvCalculator.h"
#include "MerkleTree.h"

#include <libcrypto/sha1.h>

bool verify_header(std::ifstream& inputStream, sce_ng_pfs_header_t& header, unsigned char* secret)
{
   //verify header signature
   
   char rsa_sig0_copy[0x100];
   char icv_hmac_sig_copy[0x100];
   
   memcpy(rsa_sig0_copy, header.rsa_sig0, 0x100);
   memcpy(icv_hmac_sig_copy, header.header_sig, 0x14);
   memset(header.header_sig, 0, 0x14);
   memset(header.rsa_sig0, 0, 0x100);

   sha1_hmac(secret, 0x14, header.magic, 0x160, header.header_sig);

   if(memcmp(header.header_sig, icv_hmac_sig_copy, 0x14) != 0)
   {
      std::cout << "header signature is invalid" << std::endl;
      return false;
   }

   //verify root_icv

   //save current position
   int64_t chunksBeginPos = inputStream.tellg();

   int64_t offset = page2off(header.root_icv_page_number, header.pageSize);
   inputStream.seekg(offset, std::ios_base::beg);
   unsigned char root_block_raw_data[0x400];
   inputStream.read((char*)root_block_raw_data, 0x400);

   //seek back to the beginning of tail
   inputStream.seekg(chunksBeginPos, std::ios_base::beg);

   /*
   sce_ng_pfs_block_t root_node;
   inputStream.read((char*)&root_node.header, sizeof(sce_ng_pfs_block_t));
   */

   unsigned char root_icv[0x14];
   if(calculate_node_icv(header, secret, 0, root_block_raw_data, root_icv) < 0)
   {
      std::cout << "failed to calculate icv" << std::endl;
      return false;
   }

   if(memcmp(root_icv, header.root_icv, 0x14) != 0)
   {
      std::cout << "root icv is invalid" << std::endl;
      return false;
   }
   
   //seek back to the beginning of tail
   inputStream.seekg(chunksBeginPos, std::ios_base::beg);

   return true;
}

bool parseFilesDb(unsigned char* klicensee, std::ifstream& inputStream, sce_ng_pfs_header_t& header, std::vector<sce_ng_pfs_block_t>& blocks)
{
   inputStream.read((char*)&header, sizeof(sce_ng_pfs_header_t));

   if(std::string((char*)header.magic, 8) != MAGIC_WORD)
   {
      std::cout << "Magic word is incorrect" << std::endl;
      return false;
   }

   //generate secret
   unsigned char secret[0x14];
   scePfsUtilGetSecret(secret, klicensee, header.files_salt, header.flags, 0, 0);

   //verify header
   if(!verify_header(inputStream, header, secret))
      return false;
   
   //save current position
   int64_t chunksBeginPos = inputStream.tellg();

   //calculate tail size
   inputStream.seekg(0, std::ios_base::end);
   int64_t cunksEndPos = inputStream.tellg();
   int64_t dataSize = cunksEndPos - chunksBeginPos;

   //confirm tail size
   if(dataSize != header.tailSize)
   {
      std::cout << "Unexpected tail size" << std::endl;
      return false;
   }

   //check version
   if(header.version != FILES_EXPECTED_VERSION_3 && header.version != FILES_EXPECTED_VERSION_5)
   {
      std::cout << "Invalid version" << std::endl;
      return false;
   }

   //flags are important for key derrivation (most likely this is flag field) - better check to know if there are any unexpected values
   if(header.flags != 0xA)
   {
      std::cout << "Unexpected flags value" << std::endl;
      return false;
   }

   //check block size
   if(header.pageSize != EXPECTED_BLOCK_SIZE)
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

   std::multimap<uint32_t, page_icv_data> page_icvs;
   unsigned char* raw_block_data = new unsigned char[header.pageSize];

   while(true)
   {
      int64_t currentBlockPos = inputStream.tellg();

      if(currentBlockPos >= cunksEndPos)
         break;

      blocks.push_back(sce_ng_pfs_block_t());
      sce_ng_pfs_block_t& block = blocks.back();

      //assign page number
      block.page = off2page(currentBlockPos, header.pageSize);

      //read header
      inputStream.read((char*)&block.header, sizeof(sce_ng_pfs_block_header_t));

      //verify header
      if(block.header.type != sce_ng_pfs_block_types::child && 
         block.header.type != sce_ng_pfs_block_types::root)
      {
         std::cout << "Unexpected type" << std::endl;
         return false;
      }

      //verify header
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

      //read hash table
      for(int32_t i = 0; i < 10; i++)
      {
         block.hashes.push_back(sce_ng_pfs_hash_t());
         sce_ng_pfs_hash_t& h = block.hashes.back();

         inputStream.read((char*)&h.data, sizeof(sce_ng_pfs_hash_t));
      }

      //validate next position - check that read operations we not out of bounds of current block
      int64_t nextBlockPos = currentBlockPos + header.pageSize;
      if((int64_t)inputStream.tellg() != nextBlockPos)
      {
         std::cout << "Block overlay" << std::endl;
         return false;
      }

      //re read block
      inputStream.seekg(-(int64_t)header.pageSize, std::ios::cur);
      inputStream.read((char*)raw_block_data, header.pageSize);

      page_icv_data icv;
      icv.offset = currentBlockPos;
      icv.page = off2page(currentBlockPos, header.pageSize);

      if(calculate_node_icv( header, secret, &block, raw_block_data, icv.icv) < 0)
      {
         std::cout << "failed to calculate icv" << std::endl;
         return false;
      }

      page_icvs.insert(std::make_pair(block.header.parent_page_number, icv));
   }

   delete[] raw_block_data;

   std::cout << "Validating hash tree..." << std::endl;

   if(!validate_merkle_tree(0, header.root_icv_page_number, blocks, page_icvs))
   {
      std::cout << "Failed to validate merkle tree" << std::endl;
      return false;
   }

   std::cout << "Hash tree is ok" << std::endl;

   return true;
}

//build child index -> parent index relationship map
bool constructDirmatrix(const std::vector<sce_ng_pfs_block_t>& blocks, std::map<uint32_t, uint32_t>& dirMatrix)
{   
   std::cout << "Building directory matrix..." << std::endl;

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
   std::cout << "Building file matrix..." << std::endl;

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
               //std::cout << "[EMPTY] File " << fileName << " index " << child << std::endl;
               continue; // can not add unexisting files - they will conflict by index in the fileMatrix!
            }
            else
            {
               //empty files should be allowed!
               std::cout << "[EMPTY] File " << fileName << " index " << child << " of type " << std::hex << block.infos[i].type << std::endl;
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
   std::cout << "Flattening file pages..." << std::endl;

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
   std::cout << "Building file paths..." << std::endl;

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
   std::cout << "Validating file paths..." << std::endl;

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

int match_file_lists(std::vector<sce_ng_pfs_file_t>& filesResult, std::set<std::string> files)
{
   std::cout << "Matching file paths..." << std::endl;

   std::set<std::string> fileResultPaths;

   for(auto& f :  filesResult)
      fileResultPaths.insert(f.path.string());

   bool print = false;
   for(auto& p : files)
   {
      if(fileResultPaths.find(p) == fileResultPaths.end())
      {
         if(!print)
         {
            std::cout << "Files not found in files.db :" << std::endl;
            print = true;
         }

         std::cout << p << std::endl;
      }
   }

   print = false;
   for(auto& p : fileResultPaths)
   {
      if(files.find(p) == files.end())
      {
         if(!print)
         {
            std::cout << "Files not found in filesystem :" << std::endl;
            print = true;
         }

         std::cout << p << std::endl;
      }
   }

   return 0;
}

//parses files.db and flattens it into file list
int parseFilesDb(unsigned char* klicensee, boost::filesystem::path titleIdPath, sce_ng_pfs_header_t& header, std::vector<sce_ng_pfs_file_t>& filesResult)
{
   std::cout << "Parsing  files.db" << std::endl;

   boost::filesystem::path root(titleIdPath);

   boost::filesystem::path filepath = root / "sce_pfs" / "files.db";
   if(!boost::filesystem::exists(filepath))
   {
      std::cout << "failed to find files.db file" << std::endl;
      return -1;
   }

   std::ifstream inputStream(filepath.generic_string().c_str(), std::ios::in | std::ios::binary);

   if(!inputStream.is_open())
   {
      std::cout << "failed to open files.db file" << std::endl;
      return -1;
   }

   //parse data into raw structures
   std::vector<sce_ng_pfs_block_t> blocks;
   if(!parseFilesDb(klicensee, inputStream, header, blocks))
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
   getFileListNoPfs(root, files, directories);

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