#include <fcntl.h>  
#include <stdlib.h>  
#include <stdio.h>  

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstdint>
#include <algorithm>
#include <map>
#include <iomanip>
#include <set>

#include <boost/filesystem.hpp>
#include <boost/range/adaptor/reversed.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string.hpp>

#include "FilesDbParser.h"
#include "UnicvDbParser.h"

#include "SecretGenerator.h"
#include "NodeIcvCalculator.h"
#include "HashTree.h"
#include "FlagOperations.h"

#include <libcrypto/sha1.h>

bool verify_header_icv(std::ifstream& inputStream, sce_ng_pfs_header_t& header, unsigned char* secret)
{
   std::cout << "verifying header..." << std::endl;

   //verify header signature
   
   char rsa_sig0_copy[0x100];
   char icv_hmac_sig_copy[0x14];
   
   memcpy(rsa_sig0_copy, header.rsa_sig0, 0x100);
   memcpy(icv_hmac_sig_copy, header.header_icv, 0x14);
   memset(header.header_icv, 0, 0x14);
   memset(header.rsa_sig0, 0, 0x100);

   sha1_hmac(secret, 0x14, header.magic, 0x160, header.header_icv);

   if(memcmp(header.header_icv, icv_hmac_sig_copy, 0x14) != 0)
   {
      std::cout << "header signature is invalid" << std::endl;
      return false;
   }

   std::cout << "header signature is valid" << std::endl;

   //verify root_icv

   //save current position
   int64_t chunksBeginPos = inputStream.tellg();

   //map page to offset
   int64_t offset = page2off(header.root_icv_page_number, header.pageSize);

   //read raw data at offset
   inputStream.seekg(offset, std::ios_base::beg);
   std::vector<unsigned char> root_block_raw_data(header.pageSize);
   inputStream.read((char*)root_block_raw_data.data(), header.pageSize);

   //seek back to the beginning of the page
   inputStream.seekg(offset, std::ios_base::beg);

   //re read only header
   sce_ng_pfs_block_header_t root_node_header;
   inputStream.read((char*)&root_node_header, sizeof(sce_ng_pfs_block_header_t));

   unsigned char root_icv[0x14];
   if(calculate_node_icv(header, secret, &root_node_header, root_block_raw_data.data(), root_icv) < 0)
   {
      std::cout << "failed to calculate root icv" << std::endl;
      return false;
   }

   if(memcmp(root_icv, header.root_icv, 0x14) != 0)
   {
      std::cout << "root icv is invalid" << std::endl;
      return false;
   }

   std::cout << "root icv is valid" << std::endl;
   
   //seek back to the beginning of tail
   inputStream.seekg(chunksBeginPos, std::ios_base::beg);

   return true;
}

bool validate_header(const sce_ng_pfs_header_t& header, int64_t dataSize)
{
   //confirm tail size
   if(dataSize != header.tailSize)
   {
      std::cout << "Unexpected tail size" << std::endl;
      return false;
   }

   //check version
   if(header.version != FILES_EXPECTED_VERSION_3 && header.version != FILES_EXPECTED_VERSION_4 && header.version != FILES_EXPECTED_VERSION_5)
   {
      std::cout << "Invalid version" << std::endl;
      return false;
   }

   //check image spec
   if(scePfsCheckImage(0, header.image_spec) < 0)
   {
      std::cout << "Invalid image spec" << std::endl;
      return false;
   }
   
   //check key_id - should be 0 - we do not expect any other values or the code has to be changed
   if(header.key_id != 0)
   {
      std::cout << "Unexpected key_id" << std::endl;
      return false;
   }

   //check that order of a tree is correct
   if(header.bt_order != order_max_avail(header.pageSize))
   {
      std::cout << "Unexpected flags value" << std::endl;
      return false;
   }

   //check that order of a tree has expected value
   if(header.bt_order != 0xA)
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

   if(header.unk6 != 0xFFFFFFFFFFFFFFFF)
   {
      std::cout << "Unexpected unk6" << std::endl;
      return false;
   }

   //check padding
   if(!isZeroVector(header.padding + 0, header.padding + sizeof(header.padding)))
   {
      std::cout << "Unexpected data instead of padding" << std::endl;
      return false;
   }

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
   scePfsUtilGetSecret(secret, klicensee, header.files_salt, secret_type_to_flag(header), 0, 0);

   //verify header
   if(!verify_header_icv(inputStream, header, secret))
      return false;
   
   //save current position
   int64_t chunksBeginPos = inputStream.tellg();

   //calculate tail size
   inputStream.seekg(0, std::ios_base::end);
   int64_t cunksEndPos = inputStream.tellg();
   int64_t dataSize = cunksEndPos - chunksBeginPos;

   //validate header
   if(!validate_header(header, dataSize))
      return false;

   //seek back to the beginning of tail
   inputStream.seekg(chunksBeginPos, std::ios_base::beg);

   std::multimap<std::uint32_t, page_icv_data> page_icvs;
   std::vector<unsigned char> raw_block_data(header.pageSize);

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
      for(std::uint32_t i = 0; i < block.header.nFiles; i++)
      {
         block.files.push_back(sce_ng_pfs_file_header_t());
         sce_ng_pfs_file_header_t& fh = block.files.back();
         inputStream.read((char*)&fh, sizeof(sce_ng_pfs_file_header_t));
      }

      //skip / test / read unused data
      std::uint32_t nUnused = MAX_FILES_IN_BLOCK - block.header.nFiles;
      std::uint32_t nUnusedSize1 = nUnused * sizeof(sce_ng_pfs_file_header_t);
      if(nUnusedSize1 > 0)
      {
         std::vector<std::uint8_t> unusedData1(nUnusedSize1);
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
      for(std::uint32_t i = 0; i < 10; i++)
      {
         block.infos.push_back(sce_ng_pfs_file_info_t());
         sce_ng_pfs_file_info_t& fi = block.infos.back();
         inputStream.read((char*)&fi, sizeof(sce_ng_pfs_file_info_t));

         //check file type
         if(fi.type != sce_ng_pfs_file_types::unexisting && 
            fi.type != sce_ng_pfs_file_types::normal_file && 
            fi.type != sce_ng_pfs_file_types::normal_directory && 
            fi.type != sce_ng_pfs_file_types::unencrypted_system_file && 
            fi.type != sce_ng_pfs_file_types::encrypted_system_file && 
            fi.type != sce_ng_pfs_file_types::unk_directory && 
            fi.type != sce_ng_pfs_file_types::unencrypted_unk1 &&
            fi.type != sce_ng_pfs_file_types::encrypted_unk2)
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
      for(std::int32_t i = 0; i < 10; i++)
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
      inputStream.read((char*)raw_block_data.data(), header.pageSize);

      //calculate icv of the page
      page_icv_data icv;
      icv.offset = currentBlockPos;
      icv.page = off2page(currentBlockPos, header.pageSize);

      if(calculate_node_icv( header, secret, &block.header, raw_block_data.data(), icv.icv) < 0)
      {
         std::cout << "failed to calculate icv" << std::endl;
         return false;
      }

      //add icv to the list
      page_icvs.insert(std::make_pair(block.header.parent_page_number, icv));
   }

   std::cout << "Validating hash tree..." << std::endl;

   if(!validate_hash_tree(0, header.root_icv_page_number, blocks, page_icvs))
   {
      std::cout << "Failed to validate hash tree" << std::endl;
      return false;
   }

   std::cout << "Hash tree is ok" << std::endl;

   return true;
}

//build child index -> parent index relationship map
bool constructDirmatrix(const std::vector<sce_ng_pfs_block_t>& blocks, std::map<std::uint32_t, std::uint32_t>& dirMatrix)
{   
   std::cout << "Building directory matrix..." << std::endl;

   for(auto& block : blocks)
   {
      for(std::uint32_t i = 0; i < block.header.nFiles; i++)
      {
         if(block.infos[i].type != sce_ng_pfs_file_types::normal_directory && block.infos[i].type != sce_ng_pfs_file_types::unk_directory)
            continue;

         std::uint32_t child = block.infos[i].idx;
         std::uint32_t parent = block.files[i].index;

         std::string fileName = std::string((const char*)block.files[i].fileName);

         if(block.infos[i].size != 0)
         {
            std::cout << "[WARNING] Directory " << fileName << " size is invalid" << std::endl;
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
bool constructFileMatrix(std::vector<sce_ng_pfs_block_t>& blocks, std::map<std::uint32_t, std::uint32_t>& fileMatrix)
{
   std::cout << "Building file matrix..." << std::endl;

   for(auto& block : blocks)
   {
      for(std::uint32_t i = 0; i < block.header.nFiles; i++)
      {
         if(block.infos[i].type == sce_ng_pfs_file_types::normal_directory || block.infos[i].type == sce_ng_pfs_file_types::unk_directory)
            continue;

         std::uint32_t child = block.infos[i].idx;
         std::uint32_t parent = block.files[i].index;

         std::string fileName = std::string((const char*)block.files[i].fileName);

         if(block.infos[i].size == 0)
         {   
            if(block.infos[i].type == sce_ng_pfs_file_types::unexisting)
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
         else
         {
            if(block.infos[i].type == sce_ng_pfs_file_types::unexisting)
            {
               //for icv.db - files that are outside of sce_sys folder always dont have correct type
               //it looks like sdslot.dat also does not have correct type
               //we assume that all these files are encrypted
               std::cout << "[WARNING] Invalid file type for file " << fileName << ". assuming file is encrypted" << std::endl;

               //fixup the type so that it does not cause troubles later
               block.infos[i].type = sce_ng_pfs_file_types::normal_file;
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
bool flattenBlocks(std::vector<sce_ng_pfs_block_t>& blocks, std::vector<sce_ng_pfs_flat_block_t>& flatBlocks)
{
   std::cout << "Flattening file pages..." << std::endl;

   for(auto& block : blocks)
   {
      for(std::uint32_t i = 0; i < block.header.nFiles; i++)
      {
         //have to skip unexisting files
         if(block.infos[i].type == sce_ng_pfs_file_types::unexisting)
         {
            //adding additional check here - only empty files may have unexisting types
            if(block.infos[i].size == 0)
            {
               continue;
            }
            else
            {
               std::string fileName = std::string((const char*)block.files[i].fileName);
               std::cout << "invalid file type for file " << fileName << std::endl;
               return false;
            }
         }
            
         flatBlocks.push_back(sce_ng_pfs_flat_block_t());
         sce_ng_pfs_flat_block_t& fb = flatBlocks.back();

         fb.header = block.header;
         fb.file = block.files[i];
         fb.info = block.infos[i];
         fb.hash = block.hashes[i];
      }
   }

   return true;
}

//find directory flat block by index
const std::vector<sce_ng_pfs_flat_block_t>::const_iterator findFlatBlockDir(const std::vector<sce_ng_pfs_flat_block_t>& flatBlocks, std::uint32_t index)
{
   size_t i = 0;
   for(auto& block : flatBlocks)
   {
      if((block.info.idx == index && block.info.type == sce_ng_pfs_file_types::normal_directory) ||
         (block.info.idx == index && block.info.type == sce_ng_pfs_file_types::unk_directory))
         return flatBlocks.begin() + i;
      i++;
   }
   return flatBlocks.end();
}

//find file flat block by index
const std::vector<sce_ng_pfs_flat_block_t>::const_iterator findFlatBlockFile(const std::vector<sce_ng_pfs_flat_block_t>& flatBlocks, std::uint32_t index)
{
   size_t i = 0;
   for(auto& block : flatBlocks)
   {
      if((block.info.idx == index && block.info.type != sce_ng_pfs_file_types::normal_directory) &&
         (block.info.idx == index && block.info.type != sce_ng_pfs_file_types::unk_directory))
         return flatBlocks.begin() + i;
      i++;
   }
   return flatBlocks.end();
}

bool constructDirPaths(boost::filesystem::path rootPath, std::map<std::uint32_t, std::uint32_t>& dirMatrix, const std::vector<sce_ng_pfs_flat_block_t>& flatBlocks, std::vector<sce_ng_pfs_dir_t>& dirsResult)
{
   std::cout << "Building dir paths..." << std::endl;

   for(auto& dir_entry : dirMatrix)
   {
      //start searching from dir up to root
      std::uint32_t childIndex = dir_entry.first;
      std::uint32_t parentIndex = dir_entry.second;

      std::vector<std::uint32_t> indexes;

      //search till the root - get all indexes for the path
      while(parentIndex != 0)
      {
         auto directory = dirMatrix.find(parentIndex);
         if(directory == dirMatrix.end())
         {
            std::cout << "Missing parent directory index " << parentIndex  << std::endl;
            return false;
         }
         
         indexes.push_back(directory->first); //child - directory that was found
         parentIndex = directory->second; //parent - specify next directory to search
      }

      //find dir flat block
      auto dirFlatBlock = findFlatBlockDir(flatBlocks, childIndex);
      if(dirFlatBlock == flatBlocks.end())
      {
         std::cout << "Missing dir with index" << childIndex << std::endl;
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

      //get dir name
      std::string dirName((const char*)dirFlatBlock->file.fileName);

      //construct full path
      boost::filesystem::path path = rootPath;
      for(auto& dname : boost::adaptors::reverse(dirNames))
      {
         path /= dname;
      }
      path /= dirName;

      //use generic string here to normalize the path !
      sce_junction p(path.generic_string());

      dirsResult.push_back(sce_ng_pfs_dir_t(p));
      sce_ng_pfs_dir_t& ft = dirsResult.back();
      ft.dir = *dirFlatBlock;
      ft.dirs = dirFlatBlocks;
   }

   return true;
}

//convert list of flat blocks to list of file paths
//rootPath - [input]
//dirMatrix - connection matrix for directories [input]
//fileMatrix - connection matrix for files [input]
//flatBlocks - flat list of blocks in files.db [input]
//filesResult - list of filepaths linked to file flat block and directory flat blocks
bool constructFilePaths(boost::filesystem::path rootPath, std::map<std::uint32_t, std::uint32_t>& dirMatrix, const std::map<std::uint32_t, std::uint32_t>& fileMatrix, const std::vector<sce_ng_pfs_flat_block_t>& flatBlocks, std::vector<sce_ng_pfs_file_t>& filesResult)
{
   std::cout << "Building file paths..." << std::endl;

   for(auto& file_entry : fileMatrix)
   {
      //start searching from file up to root
      std::uint32_t childIndex = file_entry.first;
      std::uint32_t parentIndex = file_entry.second;

      std::vector<std::uint32_t> indexes;

      //search till the root - get all indexes for the path
      while(parentIndex != 0)
      {
         auto directory = dirMatrix.find(parentIndex);
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

      //use generic string here to normalize the path !
      sce_junction p(path.generic_string());

      filesResult.push_back(sce_ng_pfs_file_t(p));
      sce_ng_pfs_file_t& ft = filesResult.back();
      ft.file = *fileFlatBlock;
      ft.dirs = dirFlatBlocks;
   }

   return true;
}

std::string fileTypeToString(sce_ng_pfs_file_types ft)
{
   switch(ft)
   {
   case sce_ng_pfs_file_types::unexisting:
      return "unexisting";
   case sce_ng_pfs_file_types::normal_file:
      return "normal_file";
   case sce_ng_pfs_file_types::normal_directory:
      return "normal_directory";
   case sce_ng_pfs_file_types::unk_directory:
      return "unk_directory";
   case sce_ng_pfs_file_types::unencrypted_system_file:
      return "unencrypted_system_file";
   case sce_ng_pfs_file_types::encrypted_system_file:
      return "encrypted_system_file";
   default:
      return "unknown";
   }
}

//checks that directory exists
bool linkDirpaths(std::vector<sce_ng_pfs_dir_t>& dirs, std::set<boost::filesystem::path> real_directories)
{
   std::cout << "Linking dir paths..." << std::endl;

   for(auto& dir : dirs)
   {
      //comparison should be done with is_equal (upper case) so it can not be replaced by .find()
      bool found = false;
      for(auto& real_dir : real_directories)
      {
         if(dir.path().is_equal(real_dir))
         {
            dir.path().link_to_real(real_dir);
            found = true;
            break;
         }
      }
      
      if(!found)
      {
         std::cout << "Directory " << dir.path() << " does not exist" << std::endl;
         return false;
      }
   }

   return true;
}

//checks that files exist
//checks that file size is correct
bool linkFilepaths(std::uint32_t fileSectorSize, std::vector<sce_ng_pfs_file_t>& files, std::set<boost::filesystem::path> real_files)
{
   std::cout << "Linking file paths..." << std::endl;

   for(auto& file : files)
   {
      //comparison should be done with is_equal (upper case) so it can not be replaced by .find()
      bool found = false;
      for(auto& real_file : real_files)
      {
         if(file.path().is_equal(real_file))
         {
            file.path().link_to_real(real_file);
            found = true;
            break;
         }
      }

      if(!found)
      {
         std::cout << "File " << file.path() << " does not exist" << std::endl;
         return false;
      }

      boost::uintmax_t size = file.path().file_size();
      if(size != file.file.info.size)
      {
         if((size % fileSectorSize) > 0)
         {
            std::cout << "File " << file.path() << " size incorrect" << std::endl;
            return false;
         }
      }
   }

   return true;
}

//returns number of extra files in real file system which are not present in files.db
int match_file_lists(const std::vector<sce_ng_pfs_file_t>& filesResult, const std::set<boost::filesystem::path>& files)
{
   std::cout << "Matching file paths..." << std::endl;

   int real_extra = 0;

   bool print = false;
   for(auto& rp : files)
   {
      bool found = false;

      //comparison should be done with is_equal (upper case) so it can not be replaced by .find()
      for(auto& vp : filesResult)
      {
         if(vp.path().is_equal(rp))
         {
            found = true;
            break;
         }
      }

      if(!found)
      {
         if(!print)
         {
            std::cout << "Files not found in files.db (warning):" << std::endl;
            print = true;
         }

         std::cout << rp.generic_string() << std::endl;
         real_extra++;
      }
   }

   print = false;
   for(auto& vp : filesResult)
   {
      bool found = false;

      //comparison should be done with is_equal (upper case) so it can not be replaced by .find()
      for(auto& rp : files)
      {
         if(vp.path().is_equal(rp))
         {
            found = true;
            break;
         }
      }

      if(!found)
      {
         if(!print)
         {
            std::cout << "Files not found in filesystem :" << std::endl;
            print = true;
         }

         std::cout << vp.path() << std::endl;
      }
   }

   return real_extra;
}

//parses files.db and flattens it into file list
int parseFilesDb(unsigned char* klicensee, boost::filesystem::path titleIdPath, sce_ng_pfs_header_t& header, std::vector<sce_ng_pfs_file_t>& filesResult, std::vector<sce_ng_pfs_dir_t>& dirsResult)
{
   std::cout << "parsing  files.db..." << std::endl;

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
   std::map<std::uint32_t, std::uint32_t> dirMatrix;
   if(!constructDirmatrix(blocks, dirMatrix))
      return -1;

   //build child index -> parent index relationship map
   std::map<std::uint32_t, std::uint32_t> fileMatrix;
   if(!constructFileMatrix(blocks, fileMatrix))
      return -1;
   
   //convert list of blocks to list of files
   std::vector<sce_ng_pfs_flat_block_t> flatBlocks;
   if(!flattenBlocks(blocks, flatBlocks))
      return -1;

   //convert flat blocks to file paths (sometimes there are empty directories that have to be created)
   //in normal scenario without this call - they will be ignored
   if(!constructDirPaths(root, dirMatrix, flatBlocks, dirsResult))
      return -1;

   //convert flat blocks to file paths
   if(!constructFilePaths(root, dirMatrix, fileMatrix, flatBlocks, filesResult))
      return -1;

   //get the list of real filesystem paths
   std::set<boost::filesystem::path> files;
   std::set<boost::filesystem::path> directories;
   getFileListNoPfs(root, files, directories);

   //link result dirs to real filesystem
   if(!linkDirpaths(dirsResult, directories))
      return -1;

   //link result files to real filesystem
   if(!linkFilepaths(EXPECTED_FILE_SECTOR_SIZE, filesResult, files))
      return -1;

   //match files and get number of extra files that do not exist in files.db
   int numExtra = match_file_lists(filesResult, files);

   //final check of sizes
   size_t expectedSize = files.size() + directories.size() - numExtra; // allow extra files to exist
   if(expectedSize != flatBlocks.size())
   {
      std::cout << "Mismatch in number of files + directories agains number of flat blocks" << std::endl;
      return -1;
   }

   return 0;
}