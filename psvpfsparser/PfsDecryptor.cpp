#include "PfsDecryptor.h"

#include <string>
#include <vector>
#include <map>
#include <set>
#include <iostream>

#include <boost/filesystem.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string.hpp>

#include "sha1.h"

#include "Utils.h"
#include "SecretGenerator.h"
#include "UnicvDbParser.h"
#include "FilesDbParser.h"
#include "PfsCryptEngine.h"
#include "PfsKeyGenerator.h"

std::string brutforce_hashes(std::map<std::string, std::vector<uint8_t>>& fileDatas, unsigned char* secret, unsigned char* signature)
{
   //we will be checking only first sector of each file hence we can precalculate a signature_key
   //because both sectret and sector_salt will not vary
   unsigned char signature_key[0x14] = {0};
   int sector_salt = 0; //sector is most likely a salt which is logically correct in terms of xts-aes
   sha1_hmac(secret, 0x14, (unsigned char*)&sector_salt, 4, signature_key);

   std::string found_path;

   //go through each first sector of the file
   for(auto& f : fileDatas)
   {
      //calculate sector signature
      unsigned char realSignature[0x14] = {0};
      sha1_hmac(signature_key, 0x14, f.second.data(), f.second.size(), realSignature);

      //try to match the signatures
      if(memcmp(signature, realSignature, 0x14) == 0)
      {
         found_path = f.first;
         break;
      }
   }

   if(found_path.length() > 0)
   {
      //remove newly found path from the search list to reduce time with each next iteration
      fileDatas.erase(found_path);
      return found_path;
   }
   else
   {
      return std::string();
   }
}

void bruteforce_map(std::string title_id_path, unsigned char* klicensee, sce_ng_pfs_header_t& ngpfs, scei_rodb_t& fdb, std::map<uint32_t, std::string>& pageMap)
{
   boost::filesystem::path root(title_id_path);

   //check file fileSectorSize
   std::set<uint32_t> fileSectorSizes;
   for(auto& t : fdb.tables)
      fileSectorSizes.insert(t.ftHeader.fileSectorSize);

   if(fileSectorSizes.size() > 1)
   {
      std::cout << "File sector size is not unique. This bruteforce mode is not supported now" << std::endl;
      return;
   }

   uint32_t uniqueSectorSize = *fileSectorSizes.begin();

   //get all files and directories
   std::set<std::string> files;
   std::set<std::string> directories;
   getFileListNoPfs(root, files, directories);

   //pre read all the files once
   std::map<std::string, std::vector<uint8_t>> fileDatas;
   for(auto& f : files)
   {
      uintmax_t fsz = boost::filesystem::file_size(f);

      // using uniqueSectorSize here. 
      // in theory this size may vary per SCEIFTBL - this will make bruteforcing a bit harder.
      // files can not be pre read in this case
      // in practice though it does not change.
      uintmax_t fsz_limited = (fsz < uniqueSectorSize) ? fsz : uniqueSectorSize;
      
      const auto& fdt = fileDatas.insert(std::make_pair(f, std::vector<uint8_t>(fsz_limited)));

      std::ifstream in(boost::filesystem::path(f).generic_string().c_str(), std::ios::in | std::ios::binary);
      in.read((char*)fdt.first->second.data(), fsz_limited);
      in.close();
   }

   //brutforce each scei_ftbl_t record
   for(auto& t : fdb.tables)
   {
      if(t.ftHeader.nSectors > 0)
      {
         //generate secret - one secret per unicv.db page is required
         unsigned char secret[0x14];
         scePfsUtilGetSecret(secret, klicensee, ngpfs.files_salt, ngpfs.flags, t.page, 0);

         std::string found_path = brutforce_hashes(fileDatas, secret, t.blocks.front().signatures.front().data()); 
         if(found_path.length() > 0)
         {
            std::cout << "Match found: " << t.page << " " << found_path << std::endl;
            pageMap.insert(std::make_pair(t.page, found_path));
         }
         else
         {
            std::cout << "Match not found: " << t.page << std::endl;
         }
      }
   }
}

void load_page_map(std::string filepath, std::map<uint32_t, std::string>& pageMap)
{
   boost::filesystem::path fp(filepath);

   std::ifstream in(fp.generic_string().c_str());

   std::string line;
   while(std::getline(in, line))
   {
      int index = line.find(' ');
      std::string pageStr = line.substr(0, index);
      std::string path = line.substr(index + 1);
      uint32_t page = boost::lexical_cast<uint32_t>(pageStr);
      pageMap.insert(std::make_pair(page, path));
   }

   in.close();
}

CryptEngineData g_data;
CryptEngineSubctx g_sub_ctx;
std::vector<uint8_t> g_signatureTable;

void init_crypt_ctx(CryptEngineWorkCtx* work_ctx, unsigned char* klicensee, sce_ng_pfs_header_t& ngpfs, scei_rodb_t& fdb, scei_ftbl_t& table, sig_tbl_t& block, uint32_t sector_base, uint32_t tail_size, unsigned char* source)
{     
   memset(&g_data, 0, sizeof(CryptEngineData));
   g_data.klicensee = klicensee;
   g_data.files_salt = ngpfs.files_salt;
   g_data.unicv_page = table.page;
   g_data.type = 2; // unknown how to set
   g_data.pmi_bcl_flag = ngpfs.flags; //not sure
   g_data.key_id = 0;
   g_data.flag0 = 6; // unknown how to set
   g_data.block_size = table.ftHeader.fileSectorSize;

   //--------------------------------

   derive_keys_ctx drv_ctx;
   memset(&drv_ctx, 0, sizeof(derive_keys_ctx));

   drv_ctx.unk_40 = 0; // unknown how to set
   drv_ctx.sceiftbl_version = fdb.dbHeader.version;

   memcpy(drv_ctx.base_key, table.ftHeader.base_key, 0x14);

   DerivePfsKeys(&g_data, &drv_ctx); //derive dec_key, iv_key, secret

   //--------------------------------
   
   memset(&g_sub_ctx, 0, sizeof(CryptEngineSubctx));
   g_sub_ctx.opt_code = CRYPT_ENGINE_DECRYPT;
   g_sub_ctx.data = &g_data;
   g_sub_ctx.unk_10 = (unsigned char*)0;
   g_sub_ctx.unk_18 = 0;
   g_sub_ctx.nBlocksTail = 0;
   g_sub_ctx.nBlocks = block.dtHeader.nSignatures;
   g_sub_ctx.sector_base = sector_base;
   g_sub_ctx.dest_offset = 0;
   g_sub_ctx.tail_size = tail_size;

   g_signatureTable.clear();
   g_signatureTable.resize(block.signatures.size() * block.dtHeader.sigSize);
   uint32_t signatureTableOffset = 0;
   for(auto& s :  block.signatures)
   {
      memcpy(g_signatureTable.data() + signatureTableOffset, s.data(), block.dtHeader.sigSize);
      signatureTableOffset += block.dtHeader.sigSize;
   }

   g_sub_ctx.signature_table = g_signatureTable.data();
   g_sub_ctx.work_buffer0 = source;
   g_sub_ctx.work_buffer1 = source;
   
   //--------------------------------
   
   work_ctx->subctx = &g_sub_ctx;
   work_ctx->error = 0;
}

void decrypt_file(boost::filesystem::path title_id_path, boost::filesystem::path destination_root, const sce_ng_pfs_file_t& file, boost::filesystem::path filepath, unsigned char* klicensee, sce_ng_pfs_header_t& ngpfs, scei_rodb_t& fdb, scei_ftbl_t& table)
{
   //construct new path
   std::string old_root = title_id_path.generic_string();
   std::string new_root = destination_root.generic_string();
   std::string old_path = filepath.generic_string();
   boost::replace_all(old_path, old_root, new_root);
   boost::filesystem::path new_path(old_path);
   boost::filesystem::path new_directory = new_path;
   new_directory.remove_filename();

   //create all directories on the way
   boost::filesystem::create_directories(new_directory);

   //create new file

   std::ofstream outputStream(new_path.generic_string().c_str(), std::ios::out | std::ios::trunc | std::ios::binary);

   //do decryption

   uintmax_t fileSize = boost::filesystem::file_size(filepath);

   std::ifstream inputStream(filepath.generic_string().c_str(), std::ios::in | std::ios::binary);

   //if number of sectors is less than or same to number that fits into single signature page
   if(table.ftHeader.nSectors <= table.ftHeader.binTreeNumMaxAvail)
   {
      std::vector<uint8_t> buffer(fileSize);
      inputStream.read((char*)buffer.data(), fileSize);
         
      uint32_t tail_size = fileSize % table.ftHeader.fileSectorSize;
         
      CryptEngineWorkCtx work_ctx;
      init_crypt_ctx(&work_ctx, klicensee, ngpfs, fdb, table, table.blocks.front(), 0, tail_size, buffer.data());

      pfs_decrypt(&work_ctx);

      if(work_ctx.error < 0)
      {
         std::cout << "Crypto Engine failed" << std::endl;
      }
      else
      {
         outputStream.write((char*)buffer.data(), fileSize);
      }
   }
   //if there are multiple signature pages
   else
   {
      uintmax_t bytes_left = fileSize;

      uintmax_t sector_base = 0;

      //go through each block of sectors
      for(auto& b : table.blocks)
      {
         //if number of sectors is less than number that fits into single signature page
         if(b.dtHeader.nSignatures < table.ftHeader.binTreeNumMaxAvail)
         {
            uint32_t full_block_size = table.ftHeader.binTreeNumMaxAvail * table.ftHeader.fileSectorSize;

            if(bytes_left >= full_block_size)
            {
               std::cout << "Invalid data size" << std::endl;
               return;
            }

            std::vector<uint8_t> buffer(bytes_left);
            inputStream.read((char*)buffer.data(), bytes_left);

            uint32_t tail_size = bytes_left % table.ftHeader.fileSectorSize;
         
            CryptEngineWorkCtx work_ctx;
            init_crypt_ctx(&work_ctx, klicensee, ngpfs, fdb, table, b, sector_base, tail_size, buffer.data());

            pfs_decrypt(&work_ctx);

            if(work_ctx.error < 0)
            {
               std::cout << "Crypto Engine failed" << std::endl;
            }
            else
            {
               outputStream.write((char*)buffer.data(), bytes_left);
            }
         }
         else
         {
            uint32_t data_size = table.ftHeader.binTreeNumMaxAvail * table.ftHeader.fileSectorSize;

            if(bytes_left < data_size)
            {
               std::cout << "Invalid data size" << std::endl;
               return;
            }

            std::vector<uint8_t> buffer(data_size);
            inputStream.read((char*)buffer.data(), data_size);

            CryptEngineWorkCtx work_ctx;
            init_crypt_ctx(&work_ctx, klicensee, ngpfs, fdb, table, b, sector_base, table.ftHeader.fileSectorSize, buffer.data());

            pfs_decrypt(&work_ctx);

            if(work_ctx.error < 0)
            {
               std::cout << "Crypto Engine failed" << std::endl;
            }
            else
            {
               outputStream.write((char*)buffer.data(), data_size);
            }

            bytes_left = bytes_left - data_size;
            sector_base = sector_base + table.ftHeader.binTreeNumMaxAvail;
         }
      }
   }
   
   inputStream.close();

   outputStream.close();
}

std::vector<sce_ng_pfs_file_t>::const_iterator find_file_by_path(std::vector<sce_ng_pfs_file_t>& files, boost::filesystem::path p)
{
   for(std::vector<sce_ng_pfs_file_t>::const_iterator it = files.begin(); it != files.end(); ++it)
   {
      if(it->path == p)
         return it; 
   }
   return files.end();
}

void decrypt_files(boost::filesystem::path title_id_path, boost::filesystem::path destination_root, unsigned char* klicensee, sce_ng_pfs_header_t& ngpfs, std::vector<sce_ng_pfs_file_t>& files, scei_rodb_t& fdb, std::map<uint32_t, std::string>& pageMap)
{
   for(auto& t : fdb.tables)
   {
      if(t.ftHeader.nSectors == 0)
         continue;

      auto map_entry = pageMap.find(t.page);
      if(map_entry == pageMap.end())
      {
         std::cout << "failed to find page " << t.page << " in map" << std::endl;
         continue;
      }

      boost::filesystem::path filepath(map_entry->second);

      auto file = find_file_by_path(files, filepath);
      if(file == files.end())
      {
         std::cout << "failed to find file " << filepath << " in flat file list" << std::endl;
         continue;
      }

      if(file->file.info.type == sce_ng_pfs_file_types::unencrypted_system_file || 
         file->file.info.type == sce_ng_pfs_file_types::directory ||
         file->file.info.type == sce_ng_pfs_file_types::unexisting)
         continue;

      decrypt_file(title_id_path, destination_root, *file, filepath, klicensee, ngpfs, fdb, t);

      std::cout << "Decrypted: " << filepath.generic_string() << std::endl;
   }
}