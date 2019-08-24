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

//------------ type functions -----------------

bool is_directory(sce_ng_pfs_file_types type)
{
   return type == sce_ng_pfs_file_types::normal_directory || 
          type == sce_ng_pfs_file_types::sys_directory || 
          type == sce_ng_pfs_file_types::acid_directory;
}

bool is_valid_file_type(sce_ng_pfs_file_types type)
{
   return type == sce_ng_pfs_file_types::unexisting || 
          type == sce_ng_pfs_file_types::normal_file || 
          type == sce_ng_pfs_file_types::normal_directory ||
          type == sce_ng_pfs_file_types::unencrypted_system_file_rw ||
          type == sce_ng_pfs_file_types::encrypted_system_file_rw ||
          type == sce_ng_pfs_file_types::sys_directory || 
          type == sce_ng_pfs_file_types::unencrypted_system_file_ro ||
          type == sce_ng_pfs_file_types::encrypted_system_file_ro ||
          type == sce_ng_pfs_file_types::acid_directory;
}

bool is_encrypted(sce_ng_pfs_file_types type)
{
   return type == sce_ng_pfs_file_types::encrypted_system_file_rw ||
          type == sce_ng_pfs_file_types::encrypted_system_file_ro || 
          type == sce_ng_pfs_file_types::normal_file;
}

bool is_unencrypted(sce_ng_pfs_file_types type)
{
   return type == sce_ng_pfs_file_types::unencrypted_system_file_rw ||
          type == sce_ng_pfs_file_types::unencrypted_system_file_ro;
}

bool is_unexisting(sce_ng_pfs_file_types type)
{
   return type == sce_ng_pfs_file_types::unexisting;
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
   case sce_ng_pfs_file_types::sys_directory:
      return "sys_directory";
   case sce_ng_pfs_file_types::acid_directory:
      return "acid_dir";
   case sce_ng_pfs_file_types::unencrypted_system_file_rw:
      return "unencrypted_system_file_rw";
   case sce_ng_pfs_file_types::encrypted_system_file_rw:
      return "encrypted_system_file_rw";
   case sce_ng_pfs_file_types::unencrypted_system_file_ro:
      return "unencrypted_system_file_ro";
   case sce_ng_pfs_file_types::encrypted_system_file_ro:
      return "encrypted_system_file_ro";
   default:
      return "unknown";
   }
}

//------------ implementation -----------------

FilesDbParser::FilesDbParser(std::shared_ptr<ICryptoOperations> cryptops, std::shared_ptr<IF00DKeyEncryptor> iF00D, std::ostream& output, 
                             const unsigned char* klicensee, boost::filesystem::path titleIdPath)
   : m_cryptops(cryptops), m_iF00D(iF00D), m_output(output), m_titleIdPath(titleIdPath)
{
   memcpy(m_klicensee, klicensee, 0x10);
}

bool FilesDbParser::verify_header_icv(std::ifstream& inputStream, const unsigned char* secret)
{
   m_output << "verifying header..." << std::endl;

   //verify header signature
   
   char rsa_sig0_copy[0x100];
   char icv_hmac_sig_copy[0x14];
   
   memcpy(rsa_sig0_copy, m_header.rsa_sig0, 0x100);
   memcpy(icv_hmac_sig_copy, m_header.header_icv, 0x14);
   memset(m_header.header_icv, 0, 0x14);
   memset(m_header.rsa_sig0, 0, 0x100);

   m_cryptops->hmac_sha1(m_header.magic, m_header.header_icv, 0x160, secret, 0x14);

   if(memcmp(m_header.header_icv, icv_hmac_sig_copy, 0x14) != 0)
   {
      m_output << "header signature is invalid" << std::endl;
      return false;
   }

   m_output << "header signature is valid" << std::endl;

   //verify root_icv

   //save current position
   int64_t chunksBeginPos = inputStream.tellg();

   //map page to offset
   int64_t offset = page2off(m_header.root_icv_page_number, m_header.pageSize);

   //read raw data at offset
   inputStream.seekg(offset, std::ios_base::beg);
   std::vector<unsigned char> root_block_raw_data(m_header.pageSize);
   inputStream.read((char*)root_block_raw_data.data(), m_header.pageSize);

   //seek back to the beginning of the page
   inputStream.seekg(offset, std::ios_base::beg);

   //re read only header
   sce_ng_pfs_block_header_t root_node_header;
   inputStream.read((char*)&root_node_header, sizeof(sce_ng_pfs_block_header_t));

   unsigned char root_icv[0x14];
   if(calculate_node_icv(m_cryptops, m_header, secret, &root_node_header, root_block_raw_data.data(), root_icv) < 0)
   {
      m_output << "failed to calculate root icv" << std::endl;
      return false;
   }

   if(memcmp(root_icv, m_header.root_icv, 0x14) != 0)
   {
      m_output << "root icv is invalid" << std::endl;
      return false;
   }

   m_output << "root icv is valid" << std::endl;
   
   //seek back to the beginning of tail
   inputStream.seekg(chunksBeginPos, std::ios_base::beg);

   return true;
}

bool FilesDbParser::get_isUnicv(bool& isUnicv)
{
   boost::filesystem::path root(m_titleIdPath);

   boost::filesystem::path filepath = root / "sce_pfs" / "unicv.db";

   if(!boost::filesystem::exists(filepath))
   {
      boost::filesystem::path filepath2 = root / "sce_pfs" / "icv.db";
      if(!boost::filesystem::exists(filepath2) || !boost::filesystem::is_directory(filepath2))
      {
         m_output << "failed to find unicv.db file or icv.db folder" << std::endl;

         isUnicv = false;
         return false;
      }
      else
      {
         isUnicv = false;
         return true;
      }
   }
   else
   {
      isUnicv = true;
      return true;
   }
}

bool FilesDbParser::validate_header(uint32_t dataSize)
{
   //confirm tail size
   if(dataSize != m_header.tailSize)
   {
      m_output << "Unexpected tail size" << std::endl;
      return false;
   }

   //check version
   if(m_header.version != FILES_EXPECTED_VERSION_3 && m_header.version != FILES_EXPECTED_VERSION_4 && m_header.version != FILES_EXPECTED_VERSION_5)
   {
      m_output << "Invalid version" << std::endl;
      return false;
   }

   //check image spec
   {
      bool isUnicv = false;
      if(!get_isUnicv(isUnicv))
         return false;

      std::vector<pfs_image_types> possibleTypes;
      is_unicv_to_img_types(isUnicv, possibleTypes);

      bool found = false;
      for(auto pt : possibleTypes)
      {
         if(scePfsCheckImage(img_type_to_mode_index(pt), m_header.image_spec) == 0)
         {
            found = true;
            break;
         }
      }

      if(!found)
      {
         m_output << "Invalid image spec" << std::endl;
         return false;
      }
   }
   
   //check key_id - should be 0 - we do not expect any other values or the code has to be changed
   if(m_header.key_id != 0)
   {
      m_output << "Unexpected key_id" << std::endl;
      return false;
   }

   //check that order of a tree is correct
   if(m_header.bt_order != order_max_avail(m_header.pageSize))
   {
      m_output << "Unexpected flags value" << std::endl;
      return false;
   }

   //check that order of a tree has expected value
   if(m_header.bt_order != 0xA)
   {
      m_output << "Unexpected flags value" << std::endl;
      return false;
   }

   //check block size
   if(m_header.pageSize != EXPECTED_BLOCK_SIZE)
   {
      m_output << "Invalid block size" << std::endl;
      return false;
   }

   if(m_header.unk6 != 0xFFFFFFFFFFFFFFFF && m_header.unk6 != 0x400)
   {
      m_output << "Unexpected unk6" << std::endl;
      return false;
   }

   //check padding
   if(!isZeroVector(m_header.padding + 0, m_header.padding + sizeof(m_header.padding)))
   {
      m_output << "Unexpected data instead of padding" << std::endl;
      return false;
   }

   return true;
}

bool FilesDbParser::parseFilesDb(std::ifstream& inputStream, std::vector<sce_ng_pfs_block_t>& blocks)
{
   inputStream.read((char*)&m_header, sizeof(sce_ng_pfs_header_t));

   if(std::string((char*)m_header.magic, 8) != MAGIC_WORD)
   {
      m_output << "Magic word is incorrect" << std::endl;
      return false;
   }

   //generate secret
   unsigned char secret[0x14];
   scePfsUtilGetSecret(m_cryptops, m_iF00D, secret, m_klicensee, m_header.files_salt, img_spec_to_crypto_engine_flag(m_header.image_spec), 0, 0);

   //verify header
   if(!verify_header_icv(inputStream, secret))
      return false;
   
   //save current position
   int64_t chunksBeginPos = inputStream.tellg();

   //calculate tail size
   inputStream.seekg(0, std::ios_base::end);
   int64_t cunksEndPos = inputStream.tellg();
   int64_t dataSize = cunksEndPos - chunksBeginPos;

   //validate header
   if(!validate_header(static_cast<std::uint32_t>(dataSize)))
      return false;

   //seek back to the beginning of tail
   inputStream.seekg(chunksBeginPos, std::ios_base::beg);

   std::multimap<std::uint32_t, page_icv_data> page_icvs;
   std::vector<unsigned char> raw_block_data(m_header.pageSize);

   while(true)
   {
      int64_t currentBlockPos = inputStream.tellg();

      if(currentBlockPos >= cunksEndPos)
         break;

      blocks.push_back(sce_ng_pfs_block_t());
      sce_ng_pfs_block_t& block = blocks.back();

      //assign page number
      block.page = off2page(currentBlockPos, m_header.pageSize);

      //read header
      inputStream.read((char*)&block.header, sizeof(sce_ng_pfs_block_header_t));

      //verify header
      if(block.header.type != sce_ng_pfs_block_types::child && 
         block.header.type != sce_ng_pfs_block_types::root)
      {
         m_output << "Unexpected type" << std::endl;
         return false;
      }

      //verify header
      if(block.header.padding != 0)
      {
         m_output << "Unexpected padding" << std::endl;
         return false;
      }

      //bad block with error or unknown format
      //may occur with:
      //    PCSE00434 savedata
      bool is_bad_block = false;
      if (block.header.nFiles > MAX_FILES_IN_BLOCK)
      {
         is_bad_block = true;
         block.header.nFiles = 0;
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

         if (is_bad_block)
         {
            m_output << "[WARNING] Skipping file headers in block with error or unknown format" << std::endl;
         }
         else if(!isZeroVector(unusedData1))
         {
            m_output << "Unexpected data instead of padding" << std::endl;
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
         block.m_infos.push_back(sce_ng_pfs_file_info_proxy_t());
         sce_ng_pfs_file_info_proxy_t& fi = block.m_infos.back();
         inputStream.read((char*)&fi.header, sizeof(sce_ng_pfs_file_info_t));

         //check file type
         if(!is_valid_file_type(fi.header.type))
         {
            m_output << "Unexpected file type" << std::endl;
            return false;
         }

         if(fi.header.padding0 != 0)
         {
            m_output << "Unexpected padding" << std::endl;
            return false;
         }

         if(fi.header.padding1 != 0)
         {
            m_output << "Unexpected unk1" << std::endl;
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
      int64_t nextBlockPos = currentBlockPos + m_header.pageSize;
      if((int64_t)inputStream.tellg() != nextBlockPos)
      {
         m_output << "Block overlay" << std::endl;
         return false;
      }

      //re read block
      inputStream.seekg(-(int64_t)m_header.pageSize, std::ios::cur);
      inputStream.read((char*)raw_block_data.data(), m_header.pageSize);

      //calculate icv of the page
      page_icv_data icv;
      icv.offset = currentBlockPos;
      icv.page = off2page(currentBlockPos, m_header.pageSize);

      if(calculate_node_icv(m_cryptops, m_header, secret, &block.header, raw_block_data.data(), icv.icv) < 0)
      {
         m_output << "failed to calculate icv" << std::endl;
         return false;
      }

      //add icv to the list
      page_icvs.insert(std::make_pair(block.header.parent_page_number, icv));
   }

   m_output << "Validating hash tree..." << std::endl;

   if(!validate_hash_tree(0, m_header.root_icv_page_number, blocks, page_icvs))
   {
      m_output << "Failed to validate hash tree" << std::endl;
      return false;
   }

   m_output << "Hash tree is ok" << std::endl;

   return true;
}

//build child index -> parent index relationship map
bool FilesDbParser::constructDirmatrix(const std::vector<sce_ng_pfs_block_t>& blocks, std::map<std::uint32_t, std::uint32_t>& dirMatrix)
{   
   m_output << "Building directory matrix..." << std::endl;

   for(auto& block : blocks)
   {
      for(std::uint32_t i = 0; i < block.header.nFiles; i++)
      {
         if(!is_directory(block.m_infos[i].header.type))
            continue;

         std::uint32_t child = block.m_infos[i].header.idx;
         std::uint32_t parent = block.files[i].index;

         std::string fileName = std::string((const char*)block.files[i].fileName);

         if(block.m_infos[i].header.size != 0)
         {
            m_output << "[WARNING] Directory " << fileName << " size is invalid" << std::endl;
         }

         if(child == INVALID_FILE_INDEX)
         {
            m_output << "Directory " << fileName << " index is invalid" << std::endl;
            return false;
         }

         if(dirMatrix.find(child) != dirMatrix.end())
         {
            m_output << "Directory " << fileName << " index " << child << " is not unique" << std::endl;
            return false;
         }

         dirMatrix.insert(std::make_pair(child, parent));
      }
   }

   return true;
}

//build child index -> parent index relationship map
bool FilesDbParser::constructFileMatrix(std::vector<sce_ng_pfs_block_t>& blocks, std::map<std::uint32_t, std::uint32_t>& fileMatrix)
{
   m_output << "Building file matrix..." << std::endl;

   for(auto& block : blocks)
   {
      for(std::uint32_t i = 0; i < block.header.nFiles; i++)
      {
         if(is_directory(block.m_infos[i].header.type))
            continue;

         std::uint32_t child = block.m_infos[i].header.idx;
         std::uint32_t parent = block.files[i].index;

         std::string fileName = std::string((const char*)block.files[i].fileName);

         if(block.m_infos[i].header.size == 0)
         {   
            if(is_unexisting(block.m_infos[i].header.type))
            {
               //m_output << "[EMPTY] File " << fileName << " index " << child << std::endl;
               continue; // can not add unexisting files - they will conflict by index in the fileMatrix!
            }
            else
            {
               //empty files should be allowed!
               m_output << "[EMPTY] File " << fileName << " index " << child << " of type " << std::hex << block.m_infos[i].header.type << std::endl;
            }
         }
         else
         {
            if(is_unexisting(block.m_infos[i].header.type))
            {
               //for icv.db - files that are outside of sce_sys folder always dont have correct type
               //it looks like sdslot.dat also does not have correct type
               //we assume that all these files are encrypted
               m_output << "[WARNING] Invalid file type for file " << fileName << ". assuming file is encrypted" << std::endl;

               //fixup the type so that it does not cause troubles later
               block.m_infos[i].original_type = block.m_infos[i].header.type;
               block.m_infos[i].hasFixedType = true;
               block.m_infos[i].header.type = sce_ng_pfs_file_types::normal_file;
            }
         }

         if(child == INVALID_FILE_INDEX)
         {
            m_output << "Directory " << fileName << " index is invalid" << std::endl;
            return false;
         }

         if(fileMatrix.find(child) != fileMatrix.end())
         {
            m_output << "File " << fileName << " index " << child << " is not unique" << std::endl;
            return false;
         }

         fileMatrix.insert(std::make_pair(child, parent));
      }
   }

   return true;
}

//convert list of blocks to list of files
//assign global index to files
bool FilesDbParser::flattenBlocks(const std::vector<sce_ng_pfs_block_t>& blocks, std::vector<sce_ng_pfs_flat_block_t>& flatBlocks)
{
   m_output << "Flattening file pages..." << std::endl;

   for(auto& block : blocks)
   {
      for(std::uint32_t i = 0; i < block.header.nFiles; i++)
      {
         //have to skip unexisting files
         if(is_unexisting(block.m_infos[i].header.type))
         {
            //adding additional check here - only empty files may have unexisting types
            if(block.m_infos[i].header.size == 0)
            {
               continue;
            }
            else
            {
               std::string fileName = std::string((const char*)block.files[i].fileName);
               m_output << "invalid file type for file " << fileName << std::endl;
               return false;
            }
         }
            
         flatBlocks.push_back(sce_ng_pfs_flat_block_t());
         sce_ng_pfs_flat_block_t& fb = flatBlocks.back();

         fb.header = block.header;
         fb.file = block.files[i];
         fb.m_info = block.m_infos[i];
         fb.hash = block.hashes[i];
      }
   }

   return true;
}

//find directory flat block by index
const std::vector<sce_ng_pfs_flat_block_t>::const_iterator FilesDbParser::findFlatBlockDir(const std::vector<sce_ng_pfs_flat_block_t>& flatBlocks, std::uint32_t index)
{
   size_t i = 0;
   for(auto& block : flatBlocks)
   {
      if(block.m_info.header.idx == index && is_directory(block.m_info.header.type))
         return flatBlocks.begin() + i;
      i++;
   }
   return flatBlocks.end();
}

//find file flat block by index
const std::vector<sce_ng_pfs_flat_block_t>::const_iterator FilesDbParser::findFlatBlockFile(const std::vector<sce_ng_pfs_flat_block_t>& flatBlocks, std::uint32_t index)
{
   size_t i = 0;
   for(auto& block : flatBlocks)
   {
      if(block.m_info.header.idx == index && !is_directory(block.m_info.header.type))
         return flatBlocks.begin() + i;
      i++;
   }
   return flatBlocks.end();
}

bool FilesDbParser::constructDirPaths(const std::map<std::uint32_t, std::uint32_t>& dirMatrix, const std::vector<sce_ng_pfs_flat_block_t>& flatBlocks)
{
   m_output << "Building dir paths..." << std::endl;

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
            m_output << "Missing parent directory index " << parentIndex  << std::endl;
            return false;
         }
         
         indexes.push_back(directory->first); //child - directory that was found
         parentIndex = directory->second; //parent - specify next directory to search
      }

      //find dir flat block
      auto dirFlatBlock = findFlatBlockDir(flatBlocks, childIndex);
      if(dirFlatBlock == flatBlocks.end())
      {
         m_output << "Missing dir with index" << childIndex << std::endl;
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
            m_output << "Missing parent directory index " << dirIndex  << std::endl;
            return false;
         }

         dirFlatBlocks.push_back(*dirFlatBlock);
         dirNames.push_back(std::string((const char*)dirFlatBlock->file.fileName));
      }

      //get dir name
      std::string dirName((const char*)dirFlatBlock->file.fileName);

      //construct full path
      boost::filesystem::path path = m_titleIdPath;
      for(auto& dname : boost::adaptors::reverse(dirNames))
      {
         path /= dname;
      }
      path /= dirName;

      //use generic string here to normalize the path !
      sce_junction p(path.generic_string());

      m_dirs.push_back(sce_ng_pfs_dir_t(p));
      sce_ng_pfs_dir_t& ft = m_dirs.back();
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
bool FilesDbParser::constructFilePaths(const std::map<std::uint32_t, std::uint32_t>& dirMatrix, const std::map<std::uint32_t, std::uint32_t>& fileMatrix, const std::vector<sce_ng_pfs_flat_block_t>& flatBlocks)
{
   m_output << "Building file paths..." << std::endl;

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
            m_output << "Missing parent directory index " << parentIndex  << std::endl;
            return false;
         }
         
         indexes.push_back(directory->first); //child - directory that was found
         parentIndex = directory->second; //parent - specify next directory to search
      }

      //find file flat block
      auto fileFlatBlock = findFlatBlockFile(flatBlocks, childIndex);
      if(fileFlatBlock == flatBlocks.end())
      {
         m_output << "Missing file with index" << childIndex << std::endl;
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
            m_output << "Missing parent directory index " << dirIndex  << std::endl;
            return false;
         }

         dirFlatBlocks.push_back(*dirFlatBlock);
         dirNames.push_back(std::string((const char*)dirFlatBlock->file.fileName));
      }

      //get file name
      std::string fileName((const char*)fileFlatBlock->file.fileName);

      //construct full path
      boost::filesystem::path path = m_titleIdPath;
      for(auto& dname : boost::adaptors::reverse(dirNames))
      {
         path /= dname;
      }
      path /= fileName;

      //use generic string here to normalize the path !
      sce_junction p(path.generic_string());

      m_files.push_back(sce_ng_pfs_file_t(p));
      sce_ng_pfs_file_t& ft = m_files.back();
      ft.file = *fileFlatBlock;
      ft.dirs = dirFlatBlocks;
   }

   return true;
}

//checks that directory exists
bool FilesDbParser::linkDirpaths(const std::set<boost::filesystem::path> real_directories)
{
   m_output << "Linking dir paths..." << std::endl;

   for(auto& dir : m_dirs)
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
         m_output << "Directory " << dir.path() << " does not exist" << std::endl;
         return false;
      }
   }

   return true;
}

//checks that files exist
//checks that file size is correct
bool FilesDbParser::linkFilepaths(const std::set<boost::filesystem::path> real_files, std::uint32_t fileSectorSize)
{
   m_output << "Linking file paths..." << std::endl;

   for(auto& file : m_files)
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
         m_output << "File " << file.path() << " does not exist" << std::endl;
         return false;
      }

      boost::uintmax_t size = file.path().file_size();
      if(size != file.file.m_info.header.size)
      {
         if((size % fileSectorSize) > 0)
         {
            m_output << "File " << file.path() << " size incorrect" << std::endl;
            return false;
         }
      }
   }

   return true;
}

//returns number of extra files in real file system which are not present in files.db
int FilesDbParser::matchFileLists(const std::set<boost::filesystem::path>& files)
{
   m_output << "Matching file paths..." << std::endl;

   int real_extra = 0;

   bool print = false;
   for(auto& rp : files)
   {
      bool found = false;

      //comparison should be done with is_equal (upper case) so it can not be replaced by .find()
      for(auto& vp : m_files)
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
            m_output << "Files not found in files.db (warning):" << std::endl;
            print = true;
         }

         m_output << rp.generic_string() << std::endl;
         real_extra++;
      }
   }

   print = false;
   for(auto& vp : m_files)
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
            m_output << "Files not found in filesystem :" << std::endl;
            print = true;
         }

         m_output << vp.path() << std::endl;
      }
   }

   return real_extra;
}

//parses files.db and flattens it into file list
int FilesDbParser::parse()
{
   if(!boost::filesystem::exists(m_titleIdPath))
   {
      m_output << "Root directory does not exist" << std::endl;
      return -1;
   }

   m_output << "parsing  files.db..." << std::endl;

   boost::filesystem::path filepath = m_titleIdPath / "sce_pfs" / "files.db";
   if(!boost::filesystem::exists(filepath))
   {
      m_output << "failed to find files.db file" << std::endl;
      return -1;
   }

   std::ifstream inputStream(filepath.generic_string().c_str(), std::ios::in | std::ios::binary);

   if(!inputStream.is_open())
   {
      m_output << "failed to open files.db file" << std::endl;
      return -1;
   }

   //parse data into raw structures
   std::vector<sce_ng_pfs_block_t> blocks;
   if(!parseFilesDb(inputStream, blocks))
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
   if(!constructDirPaths(dirMatrix, flatBlocks))
      return -1;

   //convert flat blocks to file paths
   if(!constructFilePaths(dirMatrix, fileMatrix, flatBlocks))
      return -1;

   //get the list of real filesystem paths
   std::set<boost::filesystem::path> files;
   std::set<boost::filesystem::path> directories;
   getFileListNoPfs(m_titleIdPath, files, directories);

   //link result dirs to real filesystem
   if(!linkDirpaths(directories))
      return -1;

   //link result files to real filesystem
   if(!linkFilepaths(files, EXPECTED_FILE_SECTOR_SIZE))
      return -1;

   //match files and get number of extra files that do not exist in files.db
   int numExtra = matchFileLists(files);

   //final check of sizes
   size_t expectedSize = files.size() + directories.size() - numExtra; // allow extra files to exist
   if(expectedSize != flatBlocks.size())
   {
      m_output << "Mismatch in number of files + directories agains number of flat blocks" << std::endl;
      return -1;
   }

   return 0;
}