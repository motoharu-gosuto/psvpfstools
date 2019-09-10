#include "PfsPageMapper.h"

#include <boost/lexical_cast.hpp>

#include "SecretGenerator.h"
#include "UnicvDbParser.h"
#include "FilesDbParser.h"

PfsPageMapper::PfsPageMapper(std::shared_ptr<ICryptoOperations> cryptops, std::shared_ptr<IF00DKeyEncryptor> iF00D, std::ostream& output, const unsigned char* klicensee, boost::filesystem::path titleIdPath)
   : m_cryptops(cryptops), m_iF00D(iF00D), m_output(output), m_titleIdPath(titleIdPath)
{
   memcpy(m_klicensee, klicensee, 0x10);
}

std::shared_ptr<sce_junction> PfsPageMapper::brutforce_hashes(const std::unique_ptr<FilesDbParser>& filesDbParser, std::map<sce_junction, std::vector<std::uint8_t>>& fileDatas, const unsigned char* secret, const unsigned char* signature) const
{
   const sce_ng_pfs_header_t& ngpfs = filesDbParser->get_header();

   unsigned char signature_key[0x14] = {0};

   if(img_spec_to_is_unicv(ngpfs.image_spec))
   {
      //we will be checking only first sector of each file hence we can precalculate a signature_key
      //because both secret and sector_salt will not vary
      int sector_salt = 0; //sector number is most likely a salt which is logically correct in terms of xts-aes
      m_cryptops->hmac_sha1((unsigned char*)&sector_salt, signature_key, 4, secret, 0x14);
   }
   else
   {
      //for icv files sector salt is not used. salt is global and is specified in the name of the file
      //this means that we can just use secret as is
      memcpy(signature_key, secret, 0x14);
   }

   //go through each first sector of the file
   for(auto& f : fileDatas)
   {
      //calculate sector signature
      unsigned char realSignature[0x14] = {0};
      m_cryptops->hmac_sha1(f.second.data(), realSignature, f.second.size(), signature_key, 0x14);

      //try to match the signatures
      if(memcmp(signature, realSignature, 0x14) == 0)
      {
         std::shared_ptr<sce_junction> found_path(new sce_junction(f.first));
         //remove newly found path from the search list to reduce time with each next iteration
         fileDatas.erase(f.first);
         return found_path;
      }
   }

   return std::shared_ptr<sce_junction>();
}

// verify one merkle tree
int PfsPageMapper::validate_merkle_tree(const std::shared_ptr<sce_iftbl_base_t> ftbl, const std::uint32_t page_idx, const std::uint32_t sig_idx, unsigned char* secret) const
{
   std::shared_ptr<sig_tbl_merkle_t> page = std::dynamic_pointer_cast<sig_tbl_merkle_t>(ftbl->m_blocks.at(page_idx));

   // is a leaf
   if (2 * sig_idx + 1 >= page->m_signatures.size())
   {
      std::uint32_t child_page_idx = page->get_child_page_idx_for_sig_idx(sig_idx);
      // is a page of height > 0
      if (child_page_idx != 0xFFFFFFFF)
         return validate_merkle_tree(ftbl, child_page_idx, 0, secret);
      return 0;
   }

   // not a leaf
   else
   {
      int ret;
      std::uint32_t left_child_idx = 2 * sig_idx + 1;
      std::uint32_t right_child_idx = left_child_idx + 1;

      // validate left and right childs
      ret = validate_merkle_tree(ftbl, page_idx, left_child_idx, secret);
      if (ret < 0)
         return ret;
      ret = validate_merkle_tree(ftbl, page_idx, right_child_idx, secret);
      if (ret < 0)
         return ret;

      // validate combined digest
      unsigned char result[0x14];
      unsigned char combined[0x28];
      memcpy(combined, page->m_signatures.at(left_child_idx)->m_data.data(), 0x14);
      memcpy(combined + 0x14, page->m_signatures.at(right_child_idx)->m_data.data(), 0x14);
      m_cryptops->hmac_sha1(combined, result, 0x28, secret, 0x14);

      if (memcmp(result, page->m_signatures.at(sig_idx)->m_data.data(), 0x14) != 0)
         return -1;
      return 0;
   }
}

// verify the merkle trees top down from the root page
int PfsPageMapper::validate_merkle_trees(const std::unique_ptr<sce_idb_base_t>& idb, const std::uint32_t files_salt, const std::uint16_t img_spec) const
{
   m_output << "Validating merkle trees..." << std::endl;

   for (auto ftbl : idb->m_tables)
   {
      // skip null tables
      if (ftbl->get_header()->get_numSectors() == 0)
         continue;

      unsigned char secret[0x14];
      scePfsUtilGetSecret(m_cryptops, m_iF00D, secret, m_klicensee, files_salt, img_spec_to_crypto_engine_flag(img_spec), ftbl->get_icv_salt(), 0);

      std::uint32_t page_idx = std::dynamic_pointer_cast<sce_icvdb_header_proxy_t>(ftbl->get_header())->get_root_page_idx();
      int ret = validate_merkle_tree(ftbl, page_idx, 0, secret);
      if (ret < 0)
         return ret;
   }

   return 0;
}

//filesDbParser and unicvDbParser are not made part of the context of PfsPageMapper
//the reason is because both filesDbParser and unicvDbParser have to be 
//initialized with parse method externally prior to calling bruteforce_map
//having filesDbParser and unicvDbParser as constructor arguments will 
//introduce ambiguity in usage of PfsPageMapper
int PfsPageMapper::bruteforce_map(const std::unique_ptr<FilesDbParser>& filesDbParser, const std::unique_ptr<UnicvDbParser>& unicvDbParser)
{
   const sce_ng_pfs_header_t& ngpfs = filesDbParser->get_header();
   const std::unique_ptr<sce_idb_base_t>& unicv = unicvDbParser->get_idatabase();

   if(img_spec_to_is_unicv(ngpfs.image_spec))
      m_output << "Building unicv.db -> files.db relation..." << std::endl;
   else
      m_output << "Building icv.db -> files.db relation..." << std::endl;

   boost::filesystem::path root(m_titleIdPath);

   //check file fileSectorSize
   std::set<std::uint32_t> fileSectorSizes;
   for(auto& t : unicv->m_tables)
   {
      //skip SCEINULL blocks
      if(t->m_blocks.size() > 0)
         fileSectorSizes.insert(t->get_header()->get_fileSectorSize());
   }

   if(fileSectorSizes.size() > 1)
   {
      m_output << "File sector size is not unique. This bruteforce mode is not supported now" << std::endl;
      return -1;
   }

   std::uint32_t uniqueSectorSize = *fileSectorSizes.begin();

   //get all files and directories
   std::set<boost::filesystem::path> files;
   std::set<boost::filesystem::path> directories;
   getFileListNoPfs(root, files, directories);

   //pre read all the files once
   std::map<sce_junction, std::vector<std::uint8_t>> fileDatas;
   for(auto& real_file : files)
   {
      sce_junction sp(real_file);
      sp.link_to_real(real_file);

      std::uintmax_t fsz = sp.file_size();

      // using uniqueSectorSize here. 
      // in theory this size may vary per SCEIFTBL - this will make bruteforcing a bit harder.
      // files can not be pre read in this case
      // in practice though it does not change.
      std::uintmax_t fsz_limited = (fsz < uniqueSectorSize) ? fsz : uniqueSectorSize;

      //empty files should be allowed!
      if(fsz_limited == 0)
      {
         m_output << "File " << sp << " is empty" << std::endl;
         m_emptyFiles.insert(sp);
      }
      else
      {
         const auto& fdt = fileDatas.insert(std::make_pair(sp, std::vector<std::uint8_t>(static_cast<std::vector<std::uint8_t>::size_type>(fsz_limited))));

         std::ifstream in;
         if(!sp.open(in))
         {
            m_output << "Failed to open " << sp << std::endl;
            return -1;
         }

         in.read((char*)fdt.first->second.data(), fsz_limited);
         in.close();
      }
   }

   //brutforce each sce_iftbl_t record
   for(auto& t : unicv->m_tables)
   {
      //process only files that are not empty
      if(t->get_header()->get_numSectors() > 0)
      {
         //generate secret - one secret per unicv.db page is required
         unsigned char secret[0x14];
         scePfsUtilGetSecret(m_cryptops, m_iF00D, secret, m_klicensee, ngpfs.files_salt, img_spec_to_crypto_engine_flag(ngpfs.image_spec), t->get_icv_salt(), 0);

         std::shared_ptr<sce_junction> found_path;

         const unsigned char* zeroSectorIcv = std::dynamic_pointer_cast<sce_iftbl_cvdb_proxy_t>(t)->get_icv_for_sector(0)->m_data.data();

         try
         {
            //try to find match by hash of zero sector
            found_path = brutforce_hashes(filesDbParser, fileDatas, secret, zeroSectorIcv);
         }
         catch(std::runtime_error& e)
         {
            m_output << e.what() << std::endl;
            return -1;
         }

         if(found_path)
         {
            m_output << "Match found: " << std::hex << t->get_icv_salt() << " " << *found_path << std::endl;
            m_pageMap.insert(std::make_pair(t->get_icv_salt(), *found_path));
         }
         else
         {
            m_output << "Match not found: " << std::hex << t->get_icv_salt() << std::endl;
            return -1;
         }
      }
   }

   //in icv - additional step checks that hash table corresponds to merkle tree
   if(!img_spec_to_is_unicv(ngpfs.image_spec))
   {
      if(validate_merkle_trees(unicv, ngpfs.files_salt, ngpfs.image_spec) < 0)
      {
         m_output << "Merkle tree is invalid." << std::endl;
         return -1;
      }
   }

   if(files.size() != (m_pageMap.size() + m_emptyFiles.size()))
   {
      m_output << "Extra files are left after mapping (warning): " << (files.size() - (m_pageMap.size() + m_emptyFiles.size())) << std::endl;
   }

   if(fileDatas.size() != 0)
   {
      for(auto& f : fileDatas)
         m_output << f.first << std::endl;
   }

   return 0;
}

//this is a test method that was supposed to be used for caching
int PfsPageMapper::load_page_map(boost::filesystem::path filepath, std::map<std::uint32_t, std::string>& pageMap) const
{
   boost::filesystem::path fp(filepath);

   if(!boost::filesystem::exists(fp))
   {
      m_output << "File " << fp.generic_string() << " does not exist" << std::endl;
      return -1;
   }

   std::ifstream in(fp.generic_string().c_str());
   if(!in.is_open())
   {
      m_output << "Failed to open " << fp.generic_string() << std::endl;
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

const std::map<std::uint32_t, sce_junction>& PfsPageMapper::get_pageMap() const
{
   return m_pageMap;
}

const std::set<sce_junction>& PfsPageMapper::get_emptyFiles() const
{
   return m_emptyFiles;
}