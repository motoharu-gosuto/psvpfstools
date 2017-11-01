#include "PfsDecryptor.h"

#include <string>
#include <vector>
#include <map>
#include <set>
#include <iostream>

#include <boost/filesystem.hpp>

#include "sha1.h"

#include "Utils.h"
#include "SecretGenerator.h"
#include "UnicvDbParser.h"
#include "FilesDbParser.h"

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

   //check file fileDbSectorSize
   std::set<uint32_t> fileSectorSizes;
   for(auto& t : fdb.tables)
      fileSectorSizes.insert(t.ftHeader.fileDbSectorSize);

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
      
      auto& fdt = fileDatas.insert(std::make_pair(f, std::vector<uint8_t>(fsz_limited)));

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
         scePfsUtilGetSecret(secret, klicensee, ngpfs.salt0, ngpfs.flags, t.page, 0);

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