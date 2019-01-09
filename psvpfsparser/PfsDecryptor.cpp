#include "PfsDecryptor.h"

#include <string>
#include <vector>
#include <map>
#include <set>
#include <iostream>

#include <boost/filesystem.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string.hpp>

#include "Utils.h"
#include "SecretGenerator.h"
#include "UnicvDbParser.h"
#include "FilesDbParser.h"

#include "PfsKeyGenerator.h"
#include "MerkleTree.hpp"

PfsFile::PfsFile(std::shared_ptr<ICryptoOperations> cryptops, std::shared_ptr<IF00DKeyEncryptor> iF00D, std::ostream& output, 
                 const unsigned char* klicensee, boost::filesystem::path titleIdPath)
   : m_cryptops(cryptops), m_iF00D(iF00D), m_output(output), m_titleIdPath(titleIdPath)
{
   memcpy(m_klicensee, klicensee, 0x10);
}

//this is a tree walker function and it should not be a part of the class
int collect_leaf(std::shared_ptr<merkle_tree_node<icv> > node, void* ctx)
{
   if(!node->isLeaf())
      return 0;

   std::vector<std::shared_ptr<merkle_tree_node<icv> > >* leaves = (std::vector<std::shared_ptr<merkle_tree_node<icv> > >*)ctx;
   leaves->push_back(node);
   return 0;
}

int PfsFile::init_crypt_ctx(CryptEngineWorkCtx* work_ctx, const sce_ng_pfs_header_t& ngpfs, const sce_ng_pfs_file_t& file, std::shared_ptr<sce_iftbl_base_t> table, sig_tbl_t& block, std::uint32_t sector_base, std::uint32_t tail_size, unsigned char* source)
{     
   memset(&m_data, 0, sizeof(CryptEngineData));
   m_data.klicensee = m_klicensee;
   m_data.files_salt = ngpfs.files_salt;
   m_data.icv_salt = table->get_icv_salt();
   m_data.mode_index = img_spec_to_mode_index(ngpfs.image_spec);
   m_data.crypto_engine_flag = img_spec_to_crypto_engine_flag(ngpfs.image_spec) | CRYPTO_ENGINE_THROW_ERROR;
   m_data.key_id = ngpfs.key_id;
   m_data.fs_attr = file.file.m_info.get_original_type();
   m_data.block_size = table->get_header()->get_fileSectorSize();

   //--------------------------------

   derive_keys_ctx drv_ctx;
   memset(&drv_ctx, 0, sizeof(derive_keys_ctx));

   drv_ctx.db_type = settings_to_db_type(m_data.mode_index, m_data.fs_attr);
   drv_ctx.icv_version = table->get_header()->get_version();

   if(is_gamedata(m_data.mode_index) && has_dbseed(drv_ctx.db_type, drv_ctx.icv_version))
      memcpy(drv_ctx.dbseed, table->get_header()->get_dbseed(), 0x14);
   else
      memset(drv_ctx.dbseed, 0, 0x14);

   setup_crypt_packet_keys(m_cryptops, m_iF00D, &m_data, &drv_ctx); //derive dec_key, tweak_enc_key, secret

   //--------------------------------
   
   memset(&m_sub_ctx, 0, sizeof(CryptEngineSubctx));
   m_sub_ctx.opt_code = CRYPT_ENGINE_READ;
   m_sub_ctx.data = &m_data;
   m_sub_ctx.work_buffer_ofst = (unsigned char*)0;
   m_sub_ctx.nBlocksOffset = 0;
   m_sub_ctx.nBlocksTail = 0;

   if(db_type_to_is_unicv(drv_ctx.db_type))
      m_sub_ctx.nBlocks = block.get_header()->get_nSignatures(); //for unicv - number of hashes is equal to number of sectors, so can use get_nSignatures
   else
      m_sub_ctx.nBlocks = table->get_header()->get_numSectors(); //for icv - there are more hashes than sectors (because of merkle tree), so have to use get_numSectors

   m_sub_ctx.sector_base = sector_base;
   m_sub_ctx.dest_offset = 0;
   m_sub_ctx.tail_size = tail_size;

   if(db_type_to_is_unicv(drv_ctx.db_type))
   {
      m_signatureTable.clear();
      m_signatureTable.resize(block.m_signatures.size() * block.get_header()->get_sigSize());
      std::uint32_t signatureTableOffset = 0;
      for(auto& s :  block.m_signatures)
      {
         memcpy(m_signatureTable.data() + signatureTableOffset, s.m_data.data(), block.get_header()->get_sigSize());
         signatureTableOffset += block.get_header()->get_sigSize();
      }
   }
   else
   {
      //for icv files we need to restore natural order of hashes in hash table (which is the order of sectors in file)

      //create merkle tree for corresponding table
      std::shared_ptr<merkle_tree<icv> > mkt = generate_merkle_tree<icv>(table->get_header()->get_numSectors());
      index_merkle_tree(mkt);

      //collect leaves
      std::vector<std::shared_ptr<merkle_tree_node<icv> > > leaves;
      walk_tree(mkt, collect_leaf, &leaves);

      if(mkt->nLeaves != leaves.size())
      {
         m_output << "Invalid number of leaves collected" << std::endl;
         return -1;
      }

      std::map<std::uint32_t, icv> naturalHashTable;

      //skip first chunk of hashes that corresponds to nodes of merkle tree (we only need to go through leaves)
      for(std::uint32_t i = mkt->nNodes - mkt->nLeaves, j = 0; i < block.m_signatures.size(); i++, j++)
      {
         naturalHashTable.insert(std::make_pair(leaves[j]->m_index, block.m_signatures[i]));
      }

      m_signatureTable.clear();
      m_signatureTable.resize(naturalHashTable.size() * block.get_header()->get_sigSize());

      std::uint32_t signatureTableOffset = 0;
      for(auto& s :  naturalHashTable)
      {
         memcpy(m_signatureTable.data() + signatureTableOffset, s.second.m_data.data(), block.get_header()->get_sigSize());
         signatureTableOffset += block.get_header()->get_sigSize();
      }
   }

   m_sub_ctx.signature_table = m_signatureTable.data();
   m_sub_ctx.work_buffer0 = source;
   m_sub_ctx.work_buffer1 = source;
   
   //--------------------------------
   
   work_ctx->subctx = &m_sub_ctx;
   work_ctx->error = 0;

   return 0;
}

int PfsFile::decrypt_icv_file(boost::filesystem::path destination_root, const sce_ng_pfs_file_t& file, const sce_junction& filepath, const sce_ng_pfs_header_t& ngpfs, std::shared_ptr<sce_iftbl_base_t> table)
{
   //create new file

   std::ofstream outputStream;
   if(!filepath.create_empty_file(m_titleIdPath, destination_root, outputStream))
      return -1;

   //open encrypted file

   std::ifstream inputStream;
   if(!filepath.open(inputStream))
   {
      m_output << "Failed to open " << filepath << std::endl;
      return -1;
   }

   //do decryption

   std::uintmax_t fileSize = filepath.file_size();

   //in icv files there are more hashes than sectors due to merkle tree
   //that is why we have to use get_numHashes() method here
   //this is different from unicv where it has one has per sector
   //we can use get_numSectors() there

   //if number of sectors is less than or same to number that fits into single signature page
   if(table->get_header()->get_numHashes() <= table->get_header()->get_binTreeNumMaxAvail())
   {
      std::vector<std::uint8_t> buffer(static_cast<std::vector<std::uint8_t>::size_type>(fileSize));
      inputStream.read((char*)buffer.data(), fileSize);
         
      std::uint32_t tail_size = fileSize % table->get_header()->get_fileSectorSize();
      if(tail_size == 0)
         tail_size = table->get_header()->get_fileSectorSize();
         
      CryptEngineWorkCtx work_ctx;
      if(init_crypt_ctx(&work_ctx, ngpfs, file, table, table->m_blocks.front(), 0, tail_size, buffer.data()) < 0)
         return -1;

      pfs_decrypt(m_cryptops, m_iF00D, &work_ctx);

      if(work_ctx.error < 0)
      {
         m_output << "Crypto Engine failed" << std::endl;
         return -1;
      }
      else
      {
         outputStream.write((char*)buffer.data(), fileSize);
      }
   }
   else
   {
      //I do not think that icv file supports more than one signature page
      //meaning that size is limited to 23 sectors
      //lets keep things simple for now
      //if it supports more than one signature page - different places in the code will have to be fixed
      m_output << "Maximum number of hashes in icv file is exceeded" << std::endl;
      return -1;
   }

   inputStream.close();

   outputStream.close();

   return 0;
}

int PfsFile::decrypt_unicv_file(boost::filesystem::path destination_root, const sce_ng_pfs_file_t& file, const sce_junction& filepath, const sce_ng_pfs_header_t& ngpfs, std::shared_ptr<sce_iftbl_base_t> table)
{
   //create new file

   std::ofstream outputStream;
   if(!filepath.create_empty_file(m_titleIdPath, destination_root, outputStream))
      return -1;

   //open encrypted file

   std::ifstream inputStream;
   if(!filepath.open(inputStream))
   {
      m_output << "Failed to open " << filepath << std::endl;
      return -1;
   }

   //do decryption

   std::uintmax_t fileSize = filepath.file_size();

   //in unicv files - there is one hash per sector
   //that is why we can use get_numSectors() method here
   //this is different from icv where it has more hashes than sectors due to merkle tree
   //we have to use get_numHashes() there

   //if number of sectors is less than or same to number that fits into single signature page
   if(table->get_header()->get_numSectors() <= table->get_header()->get_binTreeNumMaxAvail())
   {
      std::vector<std::uint8_t> buffer(static_cast<std::vector<std::uint8_t>::size_type>(fileSize));
      inputStream.read((char*)buffer.data(), fileSize);
         
      std::uint32_t tail_size = fileSize % table->get_header()->get_fileSectorSize();
      if(tail_size == 0)
         tail_size = table->get_header()->get_fileSectorSize();
         
      CryptEngineWorkCtx work_ctx;
      if(init_crypt_ctx(&work_ctx, ngpfs, file, table, table->m_blocks.front(), 0, tail_size, buffer.data()) < 0)
         return -1;

      pfs_decrypt(m_cryptops, m_iF00D, &work_ctx);

      if(work_ctx.error < 0)
      {
         m_output << "Crypto Engine failed" << std::endl;
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

      std::uint32_t sector_base = 0;

      //go through each block of sectors
      for(auto& b : table->m_blocks)
      {
         //if number of sectors is less than number that fits into single signature page
         if(b.get_header()->get_nSignatures() < table->get_header()->get_binTreeNumMaxAvail())
         {
            std::uint32_t full_block_size = table->get_header()->get_binTreeNumMaxAvail() * table->get_header()->get_fileSectorSize();

            if(bytes_left >= full_block_size)
            {
               m_output << "Invalid data size" << std::endl;
               return -1;
            }

            std::vector<std::uint8_t> buffer(static_cast<std::vector<std::uint8_t>::size_type>(bytes_left));
            inputStream.read((char*)buffer.data(), bytes_left);

            std::uint32_t tail_size = bytes_left % table->get_header()->get_fileSectorSize();
            if(tail_size == 0)
               tail_size = table->get_header()->get_fileSectorSize();
         
            CryptEngineWorkCtx work_ctx;
            if(init_crypt_ctx(&work_ctx, ngpfs, file, table, b, sector_base, tail_size, buffer.data()) < 0)
               return -1;

            pfs_decrypt(m_cryptops, m_iF00D, &work_ctx);

            if(work_ctx.error < 0)
            {
               m_output << "Crypto Engine failed" << std::endl;
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
               std::vector<std::uint8_t> buffer(static_cast<std::vector<std::uint8_t>::size_type>(bytes_left));
               inputStream.read((char*)buffer.data(), bytes_left);

               std::uint32_t tail_size = bytes_left % table->get_header()->get_fileSectorSize();
               if(tail_size == 0)
                  tail_size = table->get_header()->get_fileSectorSize();

               CryptEngineWorkCtx work_ctx;
               if(init_crypt_ctx(&work_ctx, ngpfs, file, table, b, sector_base, tail_size, buffer.data()) < 0)
                  return -1;

               pfs_decrypt(m_cryptops, m_iF00D, &work_ctx);

               if(work_ctx.error < 0)
               {
                  m_output << "Crypto Engine failed" << std::endl;
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
               if(init_crypt_ctx(&work_ctx, ngpfs, file, table, b, sector_base, table->get_header()->get_fileSectorSize(), buffer.data()) < 0)
                  return -1;

               pfs_decrypt(m_cryptops, m_iF00D, &work_ctx);

               if(work_ctx.error < 0)
               {
                  m_output << "Crypto Engine failed" << std::endl;
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

int PfsFile::decrypt_file(boost::filesystem::path destination_root, const sce_ng_pfs_file_t& file, const sce_junction& filepath, const sce_ng_pfs_header_t& ngpfs, std::shared_ptr<sce_iftbl_base_t> table)
{
   if(img_spec_to_is_unicv(ngpfs.image_spec))
      return decrypt_unicv_file(destination_root, file, filepath, ngpfs, table);
   else
      return decrypt_icv_file(destination_root, file, filepath, ngpfs, table);
}


PfsFilesystem::PfsFilesystem(std::shared_ptr<ICryptoOperations> cryptops, std::shared_ptr<IF00DKeyEncryptor> iF00D, std::ostream& output, 
                 const unsigned char* klicensee, boost::filesystem::path titleIdPath)
   : m_cryptops(cryptops), m_iF00D(iF00D), m_output(output), m_titleIdPath(titleIdPath)
{
   memcpy(m_klicensee, klicensee, 0x10);

   m_filesDbParser = std::unique_ptr<FilesDbParser>(new FilesDbParser(cryptops, iF00D, output, klicensee, titleIdPath));

   m_unicvDbParser = std::unique_ptr<UnicvDbParser>(new UnicvDbParser(titleIdPath, output));

   m_pageMapper = std::unique_ptr<PfsPageMapper>(new PfsPageMapper(cryptops, iF00D, output, klicensee, titleIdPath));
}

std::vector<sce_ng_pfs_file_t>::const_iterator PfsFilesystem::find_file_by_path(const std::vector<sce_ng_pfs_file_t>& files, const sce_junction& p)
{
   for(std::vector<sce_ng_pfs_file_t>::const_iterator it = files.begin(); it != files.end(); ++it)
   {
      if(it->path().is_equal(p))
         return it; 
   }
   return files.end();
}

int PfsFilesystem::mount()
{
   if(m_filesDbParser->parse() < 0)
      return -1;

   if(m_unicvDbParser->parse() < 0)
      return -1;

   if(m_pageMapper->bruteforce_map(m_filesDbParser, m_unicvDbParser) < 0)
      return -1;
   
   return 0;
}

int PfsFilesystem::decrypt_files(boost::filesystem::path destTitleIdPath)
{
   const sce_ng_pfs_header_t& ngpfs = m_filesDbParser->get_header();
   const std::vector<sce_ng_pfs_file_t>& files = m_filesDbParser->get_files();
   const std::vector<sce_ng_pfs_dir_t>& dirs = m_filesDbParser->get_dirs();

   const std::unique_ptr<sce_idb_base_t>& unicv = m_unicvDbParser->get_idatabase();

   const std::map<std::uint32_t, sce_junction>& pageMap = m_pageMapper->get_pageMap();
   const std::set<sce_junction>& emptyFiles = m_pageMapper->get_emptyFiles();

   m_output << "Creating directories..." << std::endl;

   for(auto& d : dirs)
   {
      if(!d.path().create_empty_directory(m_titleIdPath, destTitleIdPath))
      {
         m_output << "Failed to create: " << d.path() << std::endl;
         return -1;
      }
      else
      {
         m_output << "Created: " << d.path() << std::endl;
      }
   }

   m_output << "Creating empty files..." << std::endl;

   for(auto& f : emptyFiles)
   {
      auto file = find_file_by_path(files, f);
      if(file == files.end())
      {
         m_output << "Ignored: " << f << std::endl;
      }
      else
      {
         if(!f.create_empty_file(m_titleIdPath, destTitleIdPath))
         {
            m_output << "Failed to create: " << f << std::endl;
            return -1;
         }
         else
         {
            m_output << "Created: " << f << std::endl;
         }
      }
   }

   m_output << "Decrypting files..." << std::endl;

   for(auto& t : unicv->m_tables)
   {
      //skip empty files and directories
      if(t->get_header()->get_numSectors() == 0)
         continue;

      //find filepath by salt (filename for icv.db or page for unicv.db)
      auto map_entry = pageMap.find(t->get_icv_salt());
      if(map_entry == pageMap.end())
      {
         m_output << "failed to find page " << t->get_icv_salt() << " in map" << std::endl;
         return -1;
      }

      //find file in files.db by filepath
      sce_junction filepath = map_entry->second;
      auto file = find_file_by_path(files, filepath);
      if(file == files.end())
      {
         m_output << "failed to find file " << filepath << " in flat file list" << std::endl;
         return -1;
      }

      //directory and unexisting file are unexpected
      if(is_directory(file->file.m_info.header.type) || is_unexisting(file->file.m_info.header.type))
      {
         m_output << "Unexpected file type" << std::endl;
         return -1;
      }
      //copy unencrypted files
      else if(is_unencrypted(file->file.m_info.header.type))
      {
         if(!filepath.copy_existing_file(m_titleIdPath, destTitleIdPath))
         {
            m_output << "Failed to copy: " << filepath << std::endl;
            return -1;
         }
         else
         {
            m_output << "Copied: " << filepath << std::endl;
         }
      }
      //decrypt encrypted files
      else if(is_encrypted(file->file.m_info.header.type))
      {
         PfsFile pfsFile(m_cryptops, m_iF00D, m_output, m_klicensee, m_titleIdPath);

         if(pfsFile.decrypt_file(destTitleIdPath, *file, filepath, ngpfs, t) < 0)
         {
            m_output << "Failed to decrypt: " << filepath << std::endl;
            return -1;
         }
         else
         {
            m_output << "Decrypted: " << filepath << std::endl;
         }
      }
      else
      {
         m_output << "Unexpected file type" << std::endl;
         return -1;
      }
   }   

   return 0;
}