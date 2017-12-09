#include "PfsDecryptor.h"

#include <string>
#include <vector>
#include <map>
#include <set>
#include <iostream>

#include <boost/filesystem.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string.hpp>

#include <libcrypto/sha1.h>

#include "Utils.h"
#include "SecretGenerator.h"
#include "UnicvDbParser.h"
#include "FilesDbParser.h"
#include "PfsCryptEngine.h"
#include "PfsKeyGenerator.h"

std::string brutforce_hashes(std::map<std::string, std::vector<std::uint8_t>>& fileDatas, unsigned char* secret, unsigned char* signature)
{
   //we will be checking only first sector of each file hence we can precalculate a signature_key
   //because both sectret and sector_salt will not vary
   unsigned char signature_key[0x14] = {0};
   int sector_salt = 0; //sector number is most likely a salt which is logically correct in terms of xts-aes
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

int bruteforce_map(boost::filesystem::path titleIdPath, unsigned char* klicensee, sce_ng_pfs_header_t& ngpfs, std::shared_ptr<sce_idb_base_t> fdb, std::map<std::uint32_t, std::string>& pageMap, std::set<std::string>& emptyFiles)
{
   std::cout << "Building unicv.db -> files.db relation..." << std::endl;

   boost::filesystem::path root(titleIdPath);

   //check file fileSectorSize
   std::set<std::uint32_t> fileSectorSizes;
   for(auto& t : fdb->m_tables)
      fileSectorSizes.insert(t->get_header()->get_fileSectorSize());

   if(fileSectorSizes.size() > 1)
   {
      std::cout << "File sector size is not unique. This bruteforce mode is not supported now" << std::endl;
      return -1;
   }

   std::uint32_t uniqueSectorSize = *fileSectorSizes.begin();

   //get all files and directories
   std::set<std::string> files;
   std::set<std::string> directories;
   getFileListNoPfs(root, files, directories);

   //pre read all the files once
   std::map<std::string, std::vector<std::uint8_t>> fileDatas;
   for(auto& f : files)
   {
      std::uintmax_t fsz = boost::filesystem::file_size(f);

      // using uniqueSectorSize here. 
      // in theory this size may vary per SCEIFTBL - this will make bruteforcing a bit harder.
      // files can not be pre read in this case
      // in practice though it does not change.
      std::uintmax_t fsz_limited = (fsz < uniqueSectorSize) ? fsz : uniqueSectorSize;

      boost::filesystem::path filePath(f);

      //empty files should be allowed!
      if(fsz_limited == 0)
      {
         std::cout << "File " << filePath.generic_string() << " is empty" << std::endl;
         emptyFiles.insert(f);
      }
      else
      {
         const auto& fdt = fileDatas.insert(std::make_pair(f, std::vector<std::uint8_t>(fsz_limited)));

         if(!boost::filesystem::exists(filePath))
         {
            std::cout << "File " << filePath.generic_string() << " does not exist" << std::endl;
            return -1;
         }

         std::ifstream in(filePath.generic_string().c_str(), std::ios::in | std::ios::binary);
         if(!in.is_open())
         {
            std::cout << "Failed to open " << filePath.generic_string() << std::endl;
            return -1;
         }

         in.read((char*)fdt.first->second.data(), fsz_limited);
         in.close();
      }
   }

   //brutforce each sce_iftbl_t record
   for(auto& t : fdb->m_tables)
   {
      //process only files that are not empty
      if(t->get_header()->get_numSectors() > 0)
      {
         //generate secret - one secret per unicv.db page is required
         unsigned char secret[0x14];
         scePfsUtilGetSecret(secret, klicensee, ngpfs.files_salt, secret_type_to_flag(ngpfs), t->get_page(), 0);

         std::string found_path = brutforce_hashes(fileDatas, secret, t->m_blocks.front().m_signatures.front().data()); 
         if(found_path.length() > 0)
         {
            std::cout << "Match found: " << t->get_page() << " " << found_path << std::endl;
            pageMap.insert(std::make_pair(t->get_page(), found_path));
         }
         else
         {
            std::cout << "Match not found: " << t->get_page() << std::endl;
            return -1;
         }
      }
   }

   if(files.size() != (pageMap.size() + emptyFiles.size()))
   {
      std::cout << "Extra files are left after mapping (warning): " << (files.size() - (pageMap.size() + emptyFiles.size())) << std::endl;
   }

   if(fileDatas.size() != 0)
   {
      std::cout << "Extra files are left after mapping (warning):" << std::endl;
      for(auto& f : fileDatas)
         std::cout << f.first << std::endl;
   }

   return 0;
}

int load_page_map(boost::filesystem::path filepath, std::map<std::uint32_t, std::string>& pageMap)
{
   boost::filesystem::path fp(filepath);

   if(!boost::filesystem::exists(fp))
   {
      std::cout << "File " << fp.generic_string() << " does not exist" << std::endl;
      return -1;
   }

   std::ifstream in(fp.generic_string().c_str());
   if(!in.is_open())
   {
      std::cout << "Failed to open " << fp.generic_string() << std::endl;
      return -1;
   }

   std::string line;
   while(std::getline(in, line))
   {
      int index = line.find(' ');
      std::string pageStr = line.substr(0, index);
      std::string path = line.substr(index + 1);
      std::uint32_t page = boost::lexical_cast<std::uint32_t>(pageStr);
      pageMap.insert(std::make_pair(page, path));
   }

   in.close();

   return 0;
}

CryptEngineData g_data;
CryptEngineSubctx g_sub_ctx;
std::vector<std::uint8_t> g_signatureTable;

void init_crypt_ctx(CryptEngineWorkCtx* work_ctx, unsigned char* klicensee, sce_ng_pfs_header_t& ngpfs, std::shared_ptr<sce_iftbl_base_t> table, sig_tbl_t& block, std::uint32_t sector_base, std::uint32_t tail_size, unsigned char* source)
{     
   memset(&g_data, 0, sizeof(CryptEngineData));
   g_data.klicensee = klicensee;
   g_data.files_salt = ngpfs.files_salt;
   g_data.unicv_page = table->get_page();
   g_data.type = 2; // unknown how to set
   g_data.pmi_bcl_flag = secret_type_to_flag(ngpfs); //not sure
   g_data.key_id = 0;
   g_data.flag0 = 6; // unknown how to set
   g_data.block_size = table->get_header()->get_fileSectorSize();

   //--------------------------------

   derive_keys_ctx drv_ctx;
   memset(&drv_ctx, 0, sizeof(derive_keys_ctx));

   drv_ctx.unk_40 = 0; // unknown how to set
   drv_ctx.sceiftbl_version = table->get_header()->get_version(); // is that correct in generic way? for both games and saves/trophies?

   memcpy(drv_ctx.base_key, table->get_header()->get_base_key(), 0x14);

   DerivePfsKeys(&g_data, &drv_ctx); //derive dec_key, iv_key, secret

   //--------------------------------
   
   memset(&g_sub_ctx, 0, sizeof(CryptEngineSubctx));
   g_sub_ctx.opt_code = CRYPT_ENGINE_DECRYPT;
   g_sub_ctx.data = &g_data;
   g_sub_ctx.unk_10 = (unsigned char*)0;
   g_sub_ctx.unk_18 = 0;
   g_sub_ctx.nBlocksTail = 0;
   g_sub_ctx.nBlocks = block.get_header()->get_nSignatures();
   g_sub_ctx.sector_base = sector_base;
   g_sub_ctx.dest_offset = 0;
   g_sub_ctx.tail_size = tail_size;

   g_signatureTable.clear();
   g_signatureTable.resize(block.m_signatures.size() * block.get_header()->get_sigSize());
   std::uint32_t signatureTableOffset = 0;
   for(auto& s :  block.m_signatures)
   {
      memcpy(g_signatureTable.data() + signatureTableOffset, s.data(), block.get_header()->get_sigSize());
      signatureTableOffset += block.get_header()->get_sigSize();
   }

   g_sub_ctx.signature_table = g_signatureTable.data();
   g_sub_ctx.work_buffer0 = source;
   g_sub_ctx.work_buffer1 = source;
   
   //--------------------------------
   
   work_ctx->subctx = &g_sub_ctx;
   work_ctx->error = 0;
}

int decrypt_file(boost::filesystem::path titleIdPath, boost::filesystem::path destination_root, const sce_ng_pfs_file_t& file, boost::filesystem::path filepath, unsigned char* klicensee, sce_ng_pfs_header_t& ngpfs, std::shared_ptr<sce_iftbl_base_t> table)
{
   //construct new path
   std::string old_root = titleIdPath.generic_string();
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
   if(!outputStream.is_open())
   {
      std::cout << "Failed to open " << new_path.generic_string() << std::endl;
      return -1;
   }

   //do decryption

   std::uintmax_t fileSize = boost::filesystem::file_size(filepath);

   if(!boost::filesystem::exists(filepath))
   {
      std::cout << "File " << filepath.generic_string() << " does not exist" << std::endl;
      return -1;
   }

   std::ifstream inputStream(filepath.generic_string().c_str(), std::ios::in | std::ios::binary);
   if(!inputStream.is_open())
   {
      std::cout << "Failed to open " << filepath.generic_string() << std::endl;
      return -1;
   }

   //if number of sectors is less than or same to number that fits into single signature page
   if(table->get_header()->get_numSectors() <= table->get_header()->get_binTreeNumMaxAvail())
   {
      std::vector<std::uint8_t> buffer(fileSize);
      inputStream.read((char*)buffer.data(), fileSize);
         
      std::uint32_t tail_size = fileSize % table->get_header()->get_fileSectorSize();
      if(tail_size == 0)
         tail_size = table->get_header()->get_fileSectorSize();
         
      CryptEngineWorkCtx work_ctx;
      init_crypt_ctx(&work_ctx, klicensee, ngpfs, table, table->m_blocks.front(), 0, tail_size, buffer.data());

      pfs_decrypt(&work_ctx);

      if(work_ctx.error < 0)
      {
         std::cout << "Crypto Engine failed" << std::endl;
         return -1;
      }
      else
      {
         outputStream.write((char*)buffer.data(), fileSize);
      }
   }
   //if there are multiple signature pages
   else
   {
      std::uintmax_t bytes_left = fileSize;

      std::uintmax_t sector_base = 0;

      //go through each block of sectors
      for(auto& b : table->m_blocks)
      {
         //if number of sectors is less than number that fits into single signature page
         if(b.get_header()->get_nSignatures() < table->get_header()->get_binTreeNumMaxAvail())
         {
            std::uint32_t full_block_size = table->get_header()->get_binTreeNumMaxAvail() * table->get_header()->get_fileSectorSize();

            if(bytes_left >= full_block_size)
            {
               std::cout << "Invalid data size" << std::endl;
               return -1;
            }

            std::vector<std::uint8_t> buffer(bytes_left);
            inputStream.read((char*)buffer.data(), bytes_left);

            std::uint32_t tail_size = bytes_left % table->get_header()->get_fileSectorSize();
            if(tail_size == 0)
               tail_size = table->get_header()->get_fileSectorSize();
         
            CryptEngineWorkCtx work_ctx;
            init_crypt_ctx(&work_ctx, klicensee, ngpfs, table, b, sector_base, tail_size, buffer.data());

            pfs_decrypt(&work_ctx);

            if(work_ctx.error < 0)
            {
               std::cout << "Crypto Engine failed" << std::endl;
               return -1;
            }
            else
            {
               outputStream.write((char*)buffer.data(), bytes_left);
            }
         }
         else
         {
            std::uint32_t full_block_size = table->get_header()->get_binTreeNumMaxAvail() * table->get_header()->get_fileSectorSize();

            //if this is a last block and last sector is not fully filled
            if(bytes_left < full_block_size)
            {
               std::vector<std::uint8_t> buffer(bytes_left);
               inputStream.read((char*)buffer.data(), bytes_left);

               std::uint32_t tail_size = bytes_left % table->get_header()->get_fileSectorSize();
               if(tail_size == 0)
                  tail_size = table->get_header()->get_fileSectorSize();

               CryptEngineWorkCtx work_ctx;
               init_crypt_ctx(&work_ctx, klicensee, ngpfs, table, b, sector_base, tail_size, buffer.data());

               pfs_decrypt(&work_ctx);

               if(work_ctx.error < 0)
               {
                  std::cout << "Crypto Engine failed" << std::endl;
                  return -1;
               }
               else
               {
                  outputStream.write((char*)buffer.data(), bytes_left);
               }
            }
            //if this is a last block and last sector is fully filled
            else
            {
               std::vector<std::uint8_t> buffer(full_block_size);
               inputStream.read((char*)buffer.data(), full_block_size);

               CryptEngineWorkCtx work_ctx;
               init_crypt_ctx(&work_ctx, klicensee, ngpfs, table, b, sector_base, table->get_header()->get_fileSectorSize(), buffer.data());

               pfs_decrypt(&work_ctx);

               if(work_ctx.error < 0)
               {
                  std::cout << "Crypto Engine failed" << std::endl;
                  return -1;
               }
               else
               {
                  outputStream.write((char*)buffer.data(), full_block_size);
               }

               bytes_left = bytes_left - full_block_size;
               sector_base = sector_base + table->get_header()->get_binTreeNumMaxAvail();
            }
         }
      }
   }
   
   inputStream.close();

   outputStream.close();

   return 0;
}

int copy_existing_file(boost::filesystem::path titleIdPath, boost::filesystem::path destination_root, boost::filesystem::path filepath)
{
   //construct new path
   std::string old_root = titleIdPath.generic_string();
   std::string new_root = destination_root.generic_string();
   std::string old_path = filepath.generic_string();
   boost::replace_all(old_path, old_root, new_root);
   boost::filesystem::path new_path(old_path);
   boost::filesystem::path new_directory = new_path;
   new_directory.remove_filename();

   //create all directories on the way
   
   boost::filesystem::create_directories(new_directory);

   //copy the file

   if(boost::filesystem::exists(new_path))
      boost::filesystem::remove(new_path);
   
   boost::filesystem::copy(filepath, new_path);

   if(!boost::filesystem::exists(new_path))
   {
      std::cout << "Failed to copy: " << filepath.generic_string() << " to " << new_path.generic_string() << std::endl;
      return -1;
   }

   return 0;
}

int create_empty_file(boost::filesystem::path titleIdPath, boost::filesystem::path destination_root, boost::filesystem::path filepath)
{
   //construct new path
   std::string old_root = titleIdPath.generic_string();
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
   if(!outputStream.is_open())
   {
      std::cout << "Failed to open " << filepath.generic_string() << std::endl;
      return -1;
   }

   outputStream.close();

   return 0;
}

int create_empty_directory(boost::filesystem::path titleIdPath, boost::filesystem::path destination_root, boost::filesystem::path dirpath)
{
   //construct new path
   std::string old_root = titleIdPath.generic_string();
   std::string new_root = destination_root.generic_string();
   std::string old_path = dirpath.generic_string();
   boost::replace_all(old_path, old_root, new_root);
   boost::filesystem::path new_path(old_path);

   //create all directories on the way
   
   boost::filesystem::create_directories(new_path);

   return 0;
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

int decrypt_files(boost::filesystem::path titleIdPath, boost::filesystem::path destTitleIdPath, unsigned char* klicensee, sce_ng_pfs_header_t& ngpfs, std::vector<sce_ng_pfs_file_t>& files, std::vector<sce_ng_pfs_dir_t>& dirs, std::shared_ptr<sce_idb_base_t> fdb, std::map<std::uint32_t, std::string>& pageMap, std::set<std::string>& emptyFiles)
{
   std::cout << "Creating directories..." << std::endl;

   for(auto& d : dirs)
   {
      boost::filesystem::path filepath(d.path);
      if(create_empty_directory(titleIdPath, destTitleIdPath, filepath) < 0)
      {
         std::cout << "Failed to create: " << filepath.generic_string() << std::endl;
         return -1;
      }
      else
      {
         std::cout << "Created: " << d.path.generic_string() << std::endl;
      }
   }

   std::cout << "Creating empty files..." << std::endl;

   for(auto& f : emptyFiles)
   {
      boost::filesystem::path filepath(f);

      auto file = find_file_by_path(files, filepath);
      if(file == files.end())
      {
         std::cout << "Ignored: " << filepath.generic_string() << std::endl;
      }
      else
      {
         if(create_empty_file(titleIdPath, destTitleIdPath, filepath) < 0)
         {
            std::cout << "Failed to create: " << filepath.generic_string() << std::endl;
            return -1;
         }
         else
         {
            std::cout << "Created: " << filepath.generic_string() << std::endl;
         }
      }
   }

   std::cout << "Decrypting files..." << std::endl;

   for(auto& t : fdb->m_tables)
   {
      //skip empty files and directories
      if(t->get_header()->get_numSectors() == 0)
         continue;

      //find filepath by unicv.db page
      auto map_entry = pageMap.find(t->get_page());
      if(map_entry == pageMap.end())
      {
         std::cout << "failed to find page " << t->get_page() << " in map" << std::endl;
         return -1;
      }

      //find file in files.db by filepath
      boost::filesystem::path filepath(map_entry->second);
      auto file = find_file_by_path(files, filepath);
      if(file == files.end())
      {
         std::cout << "failed to find file " << filepath << " in flat file list" << std::endl;
         return -1;
      }

      //directory and unexisting file are unexpected
      if(file->file.info.type == sce_ng_pfs_file_types::normal_directory ||
         file->file.info.type == sce_ng_pfs_file_types::unk_directory ||
         file->file.info.type == sce_ng_pfs_file_types::unexisting)
      {
         std::cout << "Unexpected file type" << std::endl;
         return -1;
      }
      //copy unencrypted files
      else if(file->file.info.type == sce_ng_pfs_file_types::unencrypted_system_file)
      {
         if(copy_existing_file(titleIdPath, destTitleIdPath, filepath) < 0)
         {
            std::cout << "Failed to copy: " << filepath.generic_string() << std::endl;
            return -1;
         }
         else
         {
            std::cout << "Copied: " << filepath.generic_string() << std::endl;
         }
      }
      //decrypt unencrypted files
      else
      {
         if(decrypt_file(titleIdPath, destTitleIdPath, *file, filepath, klicensee, ngpfs, t) < 0)
         {
            std::cout << "Failed to decrypt: " << filepath.generic_string() << std::endl;
            return -1;
         }
         else
         {
            std::cout << "Decrypted: " << filepath.generic_string() << std::endl;
         }
      }
   }   

   return 0;
}