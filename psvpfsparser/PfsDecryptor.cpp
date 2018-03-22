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
#include "PfsCryptEngine.h"
#include "PfsKeyGenerator.h"
#include "MerkleTree.hpp"

std::shared_ptr<sce_junction> brutforce_hashes(std::shared_ptr<ICryptoOperations> cryptops, sce_ng_pfs_header_t& ngpfs, std::map<sce_junction, std::vector<std::uint8_t>>& fileDatas, const unsigned char* secret, const unsigned char* signature)
{
   unsigned char signature_key[0x14] = {0};

   if(img_spec_to_is_unicv(ngpfs.image_spec))
   {
      //we will be checking only first sector of each file hence we can precalculate a signature_key
      //because both secret and sector_salt will not vary
      int sector_salt = 0; //sector number is most likely a salt which is logically correct in terms of xts-aes
      cryptops->hmac_sha1((unsigned char*)&sector_salt, signature_key, 4, secret, 0x14);
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
      cryptops->hmac_sha1(f.second.data(), realSignature, f.second.size(), signature_key, 0x14);

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

int find_zero_sector_index(std::shared_ptr<merkle_tree_node<icv> > node, void* ctx)
{
   std::pair<std::uint32_t, std::uint32_t>* ctx_pair = (std::pair<std::uint32_t, std::uint32_t>*)ctx;

   if(node->isLeaf())
   {
      if(node->m_index == 0)
      {
         ctx_pair->second = ctx_pair->first; //save global counter to result
         return -1;
      }
      else
      {
         ctx_pair->first++; //increase global counter
         return 0;
      }
   }
   else
   {
      ctx_pair->first++; //increase global counter
      return 0;
   }
}

int assign_hash(std::shared_ptr<merkle_tree_node<icv> > node, void* ctx)
{
   if(!node->isLeaf())
      return 0;

   std::map<std::uint32_t, icv>* sectorHashMap = (std::map<std::uint32_t, icv>*)ctx;

   auto item = sectorHashMap->find(node->m_index);
   if(item == sectorHashMap->end())
      throw std::runtime_error("Missing sector hash");
      
   node->m_context.m_data.assign(item->second.m_data.begin(), item->second.m_data.end());

   return 0;
}

int combine_hash(std::shared_ptr<merkle_tree_node<icv> > result, std::shared_ptr<merkle_tree_node<icv> > left, std::shared_ptr<merkle_tree_node<icv> > right, void* ctx)
{
   unsigned char bytes28[0x28] = {0};
   memcpy(bytes28, left->m_context.m_data.data(), 0x14);
   memcpy(bytes28 + 0x14, right->m_context.m_data.data(), 0x14);

   std::pair<std::shared_ptr<ICryptoOperations>, unsigned char*>* ctx_cast = (std::pair<std::shared_ptr<ICryptoOperations>, unsigned char*>*)ctx;
   
   std::shared_ptr<ICryptoOperations> cryptops = ctx_cast->first;
   unsigned char* secret = ctx_cast->second;

   result->m_context.m_data.resize(0x14);
   cryptops->hmac_sha1(bytes28, result->m_context.m_data.data(), 0x28, secret, 0x14);

   return 0;
}

int collect_hash(std::shared_ptr<merkle_tree_node<icv> > node, void* ctx)
{
   std::vector<icv>* hashTable = (std::vector<icv>*)ctx;
   hashTable->push_back(node->m_context);
   return 0;
}

int compare_hash_tables(const std::vector<icv>& left, const std::vector<icv>& right)
{
   if(left.size() != right.size())
      return -1;
   
   for(std::size_t i = 0; i < left.size(); i++)
   {
      if(memcmp(left[i].m_data.data(), right[i].m_data.data(), 0x14) != 0)
         return -1;
   }
   
   return 0;
}

//pageMap - relates icv salt (icv filename) to junction (real file in filesystem)
//merkleTrees - relates icv table entry (icv file) to merkle tree of real file
//idea is to find icv table entry by icv filename - this way we can relate junction to merkle tree
//then we can read the file and hash it into merkle tree
//then merkle tree is collected into hash table
//then hash table is compared to the hash table from icv table entry
int validate_merkle_trees(std::shared_ptr<ICryptoOperations> cryptops, std::shared_ptr<IF00DKeyEncryptor> iF00D, unsigned char* klicensee, sce_ng_pfs_header_t& ngpfs, std::map<std::uint32_t, sce_junction>& pageMap, std::vector<std::pair<std::shared_ptr<sce_iftbl_base_t>, std::shared_ptr<merkle_tree<icv> > > >& merkleTrees)
{
   std::cout << "Validating merkle trees..." << std::endl;

   for(auto entry : merkleTrees)
   {
      //get table
      std::shared_ptr<sce_iftbl_base_t> table = entry.first;

      //calculate secret
      unsigned char secret[0x14];
      scePfsUtilGetSecret(cryptops, iF00D, secret, klicensee, ngpfs.files_salt, img_spec_to_crypto_engine_flag(ngpfs.image_spec), table->get_icv_salt(), 0);

      //find junction
      auto junctionIt = pageMap.find(table->get_icv_salt());
      if(junctionIt == pageMap.end())
      {
         std::cout << "Table item not found in page map" << std::endl;
         return -1;
      }
      
      const sce_junction& junction = junctionIt->second;

      //read junction into sector map
      std::ifstream inputStream;
      junction.open(inputStream);

      std::uint32_t sectorSize = table->get_header()->get_fileSectorSize();
      std::uintmax_t fileSize = junction.file_size(); 

      std::uint32_t nSectors = static_cast<std::uint32_t>(fileSize / sectorSize);
      std::uint32_t tailSize = fileSize % sectorSize;

      std::map<std::uint32_t, icv> sectorHashMap;

      std::vector<std::uint8_t> raw_data(sectorSize);
      for(std::uint32_t i = 0; i < nSectors; i++)
      {
         auto currentItem = sectorHashMap.insert(std::make_pair(i, icv()));
         icv& currentIcv = currentItem.first->second;

         inputStream.read((char*)raw_data.data(), sectorSize);

         currentIcv.m_data.resize(0x14);
         cryptops->hmac_sha1(raw_data.data(), currentIcv.m_data.data(), sectorSize, secret, 0x14);
      }

      if(tailSize > 0)
      {
         auto currentItem = sectorHashMap.insert(std::make_pair(nSectors, icv()));
         icv& currentIcv = currentItem.first->second;

         inputStream.read((char*)raw_data.data(), tailSize);

         currentIcv.m_data.resize(0x14);
         cryptops->hmac_sha1(raw_data.data(), currentIcv.m_data.data(), tailSize, secret, 0x14);
      }

      try
      {
         //get merkle tree (it should already be indexed)
         std::shared_ptr<merkle_tree<icv> > mkt = entry.second;

         //assign hashes to leaves
         walk_tree(mkt, assign_hash, &sectorHashMap);

         //calculate node hashes
         auto combine_ctx = std::make_pair(cryptops, secret);
         bottom_top_walk_combine(mkt, combine_hash, &combine_ctx);

         //collect hashes into table
         std::vector<icv> hashTable;
         walk_tree(mkt, collect_hash, &hashTable);

         //compare tables
         if(compare_hash_tables(hashTable, table->m_blocks.front().m_signatures) < 0)
         {
            std::cout << "Merkle tree is invalid in file " << junction << std::endl;
            return -1;
         }

         std::cout << "File: " << std::hex << table->get_icv_salt() << " [OK]" << std::endl;
      }
      catch(std::runtime_error& e)
      {
         std::cout << e.what() << std::endl;
         return -1;
      }  
   }

   return 0;
}

int bruteforce_map(std::shared_ptr<ICryptoOperations> cryptops, std::shared_ptr<IF00DKeyEncryptor> iF00D, boost::filesystem::path titleIdPath, unsigned char* klicensee, sce_ng_pfs_header_t& ngpfs, std::shared_ptr<sce_idb_base_t> fdb, std::map<std::uint32_t, sce_junction>& pageMap, std::set<sce_junction>& emptyFiles)
{
   if(img_spec_to_is_unicv(ngpfs.image_spec))
      std::cout << "Building unicv.db -> files.db relation..." << std::endl;
   else
      std::cout << "Building icv.db -> files.db relation..." << std::endl;

   boost::filesystem::path root(titleIdPath);

   //check file fileSectorSize
   std::set<std::uint32_t> fileSectorSizes;
   for(auto& t : fdb->m_tables)
   {
      //skip SCEINULL blocks
      if(t->m_blocks.size() > 0)
         fileSectorSizes.insert(t->get_header()->get_fileSectorSize());
   }

   if(fileSectorSizes.size() > 1)
   {
      std::cout << "File sector size is not unique. This bruteforce mode is not supported now" << std::endl;
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
         std::cout << "File " << sp << " is empty" << std::endl;
         emptyFiles.insert(sp);
      }
      else
      {
         const auto& fdt = fileDatas.insert(std::make_pair(sp, std::vector<std::uint8_t>(static_cast<std::vector<std::uint8_t>::size_type>(fsz_limited))));

         std::ifstream in;
         if(!sp.open(in))
         {
            std::cout << "Failed to open " << sp << std::endl;
            return -1;
         }

         in.read((char*)fdt.first->second.data(), fsz_limited);
         in.close();
      }
   }

   std::vector<std::pair<std::shared_ptr<sce_iftbl_base_t>, std::shared_ptr<merkle_tree<icv> > > > merkleTrees;

   //brutforce each sce_iftbl_t record
   for(auto& t : fdb->m_tables)
   {
      //process only files that are not empty
      if(t->get_header()->get_numSectors() > 0)
      {
         //generate secret - one secret per unicv.db page is required
         unsigned char secret[0x14];
         scePfsUtilGetSecret(cryptops, iF00D, secret, klicensee, ngpfs.files_salt, img_spec_to_crypto_engine_flag(ngpfs.image_spec), t->get_icv_salt(), 0);

         std::shared_ptr<sce_junction> found_path;

         if(img_spec_to_is_unicv(ngpfs.image_spec))
         {
            //in unicv - hash table has same order as sectors in a file
            const unsigned char* zeroSectorIcv = t->m_blocks.front().m_signatures.front().m_data.data();

            //try to find match by hash of zero sector
            found_path = brutforce_hashes(cryptops, ngpfs, fileDatas, secret, zeroSectorIcv); 
         }
         else
         {
            try
            {
               //create merkle tree for corresponding table
               std::shared_ptr<merkle_tree<icv> > mkt = generate_merkle_tree<icv>(t->get_header()->get_numSectors());
               index_merkle_tree(mkt);

               //save merkle tree
               merkleTrees.push_back(std::make_pair(t, mkt));

               //use merkle tree to find index of zero sector in hash table
               std::pair<std::uint32_t, std::uint32_t> ctx;
               walk_tree(mkt, find_zero_sector_index, &ctx);

               //in icv - hash table is ordered according to merkle tree structure
               //that is why it is required to walk through the tree to find zero sector hash in hash table
               const unsigned char* zeroSectorIcv = t->m_blocks.front().m_signatures.at(ctx.second).m_data.data();

               //try to find match by hash of zero sector
               found_path = brutforce_hashes(cryptops, ngpfs, fileDatas, secret, zeroSectorIcv);
            }
            catch(std::runtime_error& e)
            {
               std::cout << e.what() << std::endl;
               return -1;
            } 
         }

         if(found_path)
         {
            std::cout << "Match found: " << std::hex << t->get_icv_salt() << " " << *found_path << std::endl;
            pageMap.insert(std::make_pair(t->get_icv_salt(), *found_path));
         }
         else
         {
            std::cout << "Match not found: " << std::hex << t->get_icv_salt() << std::endl;
            return -1;
         }
      }
   }

   //in icv - additional step checks that hash table corresponds to merkle tree
   if(!img_spec_to_is_unicv(ngpfs.image_spec))
   {
      if(validate_merkle_trees(cryptops, iF00D, klicensee, ngpfs, pageMap, merkleTrees) < 0)
         return -1;
   }

   if(files.size() != (pageMap.size() + emptyFiles.size()))
   {
      std::cout << "Extra files are left after mapping (warning): " << (files.size() - (pageMap.size() + emptyFiles.size())) << std::endl;
   }

   if(fileDatas.size() != 0)
   {
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

int collect_leaf(std::shared_ptr<merkle_tree_node<icv> > node, void* ctx)
{
   if(!node->isLeaf())
      return 0;

   std::vector<std::shared_ptr<merkle_tree_node<icv> > >* leaves = (std::vector<std::shared_ptr<merkle_tree_node<icv> > >*)ctx;
   leaves->push_back(node);
   return 0;
}

CryptEngineData g_data;
CryptEngineSubctx g_sub_ctx;
std::vector<std::uint8_t> g_signatureTable;

int init_crypt_ctx(std::shared_ptr<ICryptoOperations> cryptops, std::shared_ptr<IF00DKeyEncryptor> iF00D, CryptEngineWorkCtx* work_ctx, unsigned char* klicensee, sce_ng_pfs_header_t& ngpfs, const sce_ng_pfs_file_t& file, std::shared_ptr<sce_iftbl_base_t> table, sig_tbl_t& block, std::uint32_t sector_base, std::uint32_t tail_size, unsigned char* source)
{     
   memset(&g_data, 0, sizeof(CryptEngineData));
   g_data.klicensee = klicensee;
   g_data.files_salt = ngpfs.files_salt;
   g_data.icv_salt = table->get_icv_salt();
   g_data.mode_index = img_spec_to_mode_index(ngpfs.image_spec);
   g_data.crypto_engine_flag = img_spec_to_crypto_engine_flag(ngpfs.image_spec) | CRYPTO_ENGINE_THROW_ERROR;
   g_data.key_id = ngpfs.key_id;
   g_data.fs_attr = file.file.m_info.get_original_type();
   g_data.block_size = table->get_header()->get_fileSectorSize();

   //--------------------------------

   derive_keys_ctx drv_ctx;
   memset(&drv_ctx, 0, sizeof(derive_keys_ctx));

   drv_ctx.db_type = settings_to_db_type(g_data.mode_index, g_data.fs_attr);
   drv_ctx.icv_version = table->get_header()->get_version();

   if(is_gamedata(g_data.mode_index) && has_dbseed(drv_ctx.db_type, drv_ctx.icv_version))
      memcpy(drv_ctx.dbseed, table->get_header()->get_dbseed(), 0x14);
   else
      memset(drv_ctx.dbseed, 0, 0x14);

   setup_crypt_packet_keys(cryptops, iF00D, &g_data, &drv_ctx); //derive dec_key, tweak_enc_key, secret

   //--------------------------------
   
   memset(&g_sub_ctx, 0, sizeof(CryptEngineSubctx));
   g_sub_ctx.opt_code = CRYPT_ENGINE_READ;
   g_sub_ctx.data = &g_data;
   g_sub_ctx.work_buffer_ofst = (unsigned char*)0;
   g_sub_ctx.nBlocksOffset = 0;
   g_sub_ctx.nBlocksTail = 0;

   if(db_type_to_is_unicv(drv_ctx.db_type))
      g_sub_ctx.nBlocks = block.get_header()->get_nSignatures(); //for unicv - number of hashes is equal to number of sectors, so can use get_nSignatures
   else
      g_sub_ctx.nBlocks = table->get_header()->get_numSectors(); //for icv - there are more hashes than sectors (because of merkle tree), so have to use get_numSectors

   g_sub_ctx.sector_base = sector_base;
   g_sub_ctx.dest_offset = 0;
   g_sub_ctx.tail_size = tail_size;

   if(db_type_to_is_unicv(drv_ctx.db_type))
   {
      g_signatureTable.clear();
      g_signatureTable.resize(block.m_signatures.size() * block.get_header()->get_sigSize());
      std::uint32_t signatureTableOffset = 0;
      for(auto& s :  block.m_signatures)
      {
         memcpy(g_signatureTable.data() + signatureTableOffset, s.m_data.data(), block.get_header()->get_sigSize());
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
         std::cout << "Invalid number of leaves collected" << std::endl;
         return -1;
      }

      std::map<std::uint32_t, icv> nartualHashTable;

      //skip first chunk of hashes that corresponds to nodes of merkle tree (we only need to go through leaves)
      for(std::uint32_t i = mkt->nNodes - mkt->nLeaves, j = 0; i < block.m_signatures.size(); i++, j++)
      {
         nartualHashTable.insert(std::make_pair(leaves[j]->m_index, block.m_signatures[i]));         
      }

      g_signatureTable.clear();
      g_signatureTable.resize(nartualHashTable.size() * block.get_header()->get_sigSize());

      std::uint32_t signatureTableOffset = 0;
      for(auto& s :  nartualHashTable)
      {
         memcpy(g_signatureTable.data() + signatureTableOffset, s.second.m_data.data(), block.get_header()->get_sigSize());
         signatureTableOffset += block.get_header()->get_sigSize();
      }
   }

   g_sub_ctx.signature_table = g_signatureTable.data();
   g_sub_ctx.work_buffer0 = source;
   g_sub_ctx.work_buffer1 = source;
   
   //--------------------------------
   
   work_ctx->subctx = &g_sub_ctx;
   work_ctx->error = 0;

   return 0;
}

int decrypt_icv_file(std::shared_ptr<ICryptoOperations> cryptops, std::shared_ptr<IF00DKeyEncryptor> iF00D, boost::filesystem::path titleIdPath, boost::filesystem::path destination_root, const sce_ng_pfs_file_t& file, const sce_junction& filepath, unsigned char* klicensee, sce_ng_pfs_header_t& ngpfs, std::shared_ptr<sce_iftbl_base_t> table)
{
   //create new file

   std::ofstream outputStream;
   if(!filepath.create_empty_file(titleIdPath, destination_root, outputStream))
      return -1;

   //open encrypted file

   std::ifstream inputStream;
   if(!filepath.open(inputStream))
   {
      std::cout << "Failed to open " << filepath << std::endl;
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
      if(init_crypt_ctx(cryptops, iF00D, &work_ctx, klicensee, ngpfs, file, table, table->m_blocks.front(), 0, tail_size, buffer.data()) < 0)
         return -1;

      pfs_decrypt(cryptops, iF00D, &work_ctx);

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
   else
   {
      //I do not think that icv file supports more than one signature page
      //meaning that size is limited to 23 sectors
      //lets keep things simple for now
      //if it supports more than one signature page - different places in the code will have to be fixed
      std::cout << "Maximum number of hashes in icv file is exceeded" << std::endl;
      return -1;
   }

   inputStream.close();

   outputStream.close();

   return 0;
}

int decrypt_unicv_file(std::shared_ptr<ICryptoOperations> cryptops, std::shared_ptr<IF00DKeyEncryptor> iF00D, boost::filesystem::path titleIdPath, boost::filesystem::path destination_root, const sce_ng_pfs_file_t& file, const sce_junction& filepath, unsigned char* klicensee, sce_ng_pfs_header_t& ngpfs, std::shared_ptr<sce_iftbl_base_t> table)
{
   //create new file

   std::ofstream outputStream;
   if(!filepath.create_empty_file(titleIdPath, destination_root, outputStream))
      return -1;

   //open encrypted file

   std::ifstream inputStream;
   if(!filepath.open(inputStream))
   {
      std::cout << "Failed to open " << filepath << std::endl;
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
      if(init_crypt_ctx(cryptops, iF00D, &work_ctx, klicensee, ngpfs, file, table, table->m_blocks.front(), 0, tail_size, buffer.data()) < 0)
         return -1;

      pfs_decrypt(cryptops, iF00D, &work_ctx);

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
               std::cout << "Invalid data size" << std::endl;
               return -1;
            }

            std::vector<std::uint8_t> buffer(static_cast<std::vector<std::uint8_t>::size_type>(bytes_left));
            inputStream.read((char*)buffer.data(), bytes_left);

            std::uint32_t tail_size = bytes_left % table->get_header()->get_fileSectorSize();
            if(tail_size == 0)
               tail_size = table->get_header()->get_fileSectorSize();
         
            CryptEngineWorkCtx work_ctx;
            if(init_crypt_ctx(cryptops, iF00D, &work_ctx, klicensee, ngpfs, file, table, b, sector_base, tail_size, buffer.data()) < 0)
               return -1;

            pfs_decrypt(cryptops, iF00D, &work_ctx);

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
               std::vector<std::uint8_t> buffer(static_cast<std::vector<std::uint8_t>::size_type>(bytes_left));
               inputStream.read((char*)buffer.data(), bytes_left);

               std::uint32_t tail_size = bytes_left % table->get_header()->get_fileSectorSize();
               if(tail_size == 0)
                  tail_size = table->get_header()->get_fileSectorSize();

               CryptEngineWorkCtx work_ctx;
               if(init_crypt_ctx(cryptops, iF00D, &work_ctx, klicensee, ngpfs, file, table, b, sector_base, tail_size, buffer.data()) < 0)
                  return -1;

               pfs_decrypt(cryptops, iF00D, &work_ctx);

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
               if(init_crypt_ctx(cryptops, iF00D, &work_ctx, klicensee, ngpfs, file, table, b, sector_base, table->get_header()->get_fileSectorSize(), buffer.data()) < 0)
                  return -1;

               pfs_decrypt(cryptops, iF00D, &work_ctx);

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

int decrypt_file(std::shared_ptr<ICryptoOperations> cryptops, std::shared_ptr<IF00DKeyEncryptor> iF00D, boost::filesystem::path titleIdPath, boost::filesystem::path destination_root, const sce_ng_pfs_file_t& file, const sce_junction& filepath, unsigned char* klicensee, sce_ng_pfs_header_t& ngpfs, std::shared_ptr<sce_iftbl_base_t> table)
{
   if(img_spec_to_is_unicv(ngpfs.image_spec))
      return decrypt_unicv_file(cryptops, iF00D, titleIdPath, destination_root, file, filepath, klicensee, ngpfs, table);
   else
      return decrypt_icv_file(cryptops, iF00D, titleIdPath, destination_root, file, filepath, klicensee, ngpfs, table);
}

std::vector<sce_ng_pfs_file_t>::const_iterator find_file_by_path(std::vector<sce_ng_pfs_file_t>& files, const sce_junction& p)
{
   for(std::vector<sce_ng_pfs_file_t>::const_iterator it = files.begin(); it != files.end(); ++it)
   {
      if(it->path().is_equal(p))
         return it; 
   }
   return files.end();
}

int decrypt_files(std::shared_ptr<ICryptoOperations> cryptops, std::shared_ptr<IF00DKeyEncryptor> iF00D, boost::filesystem::path titleIdPath, boost::filesystem::path destTitleIdPath, unsigned char* klicensee, sce_ng_pfs_header_t& ngpfs, std::vector<sce_ng_pfs_file_t>& files, std::vector<sce_ng_pfs_dir_t>& dirs, std::shared_ptr<sce_idb_base_t> fdb, std::map<std::uint32_t, sce_junction>& pageMap, std::set<sce_junction>& emptyFiles)
{
   std::cout << "Creating directories..." << std::endl;

   for(auto& d : dirs)
   {
      if(!d.path().create_empty_directory(titleIdPath, destTitleIdPath))
      {
         std::cout << "Failed to create: " << d.path() << std::endl;
         return -1;
      }
      else
      {
         std::cout << "Created: " << d.path() << std::endl;
      }
   }

   std::cout << "Creating empty files..." << std::endl;

   for(auto& f : emptyFiles)
   {
      auto file = find_file_by_path(files, f);
      if(file == files.end())
      {
         std::cout << "Ignored: " << f << std::endl;
      }
      else
      {
         if(!f.create_empty_file(titleIdPath, destTitleIdPath))
         {
            std::cout << "Failed to create: " << f << std::endl;
            return -1;
         }
         else
         {
            std::cout << "Created: " << f << std::endl;
         }
      }
   }

   std::cout << "Decrypting files..." << std::endl;

   for(auto& t : fdb->m_tables)
   {
      //skip empty files and directories
      if(t->get_header()->get_numSectors() == 0)
         continue;

      //find filepath by salt (filename for icv.db or page for unicv.db)
      auto map_entry = pageMap.find(t->get_icv_salt());
      if(map_entry == pageMap.end())
      {
         std::cout << "failed to find page " << t->get_icv_salt() << " in map" << std::endl;
         return -1;
      }

      //find file in files.db by filepath
      sce_junction filepath = map_entry->second;
      auto file = find_file_by_path(files, filepath);
      if(file == files.end())
      {
         std::cout << "failed to find file " << filepath << " in flat file list" << std::endl;
         return -1;
      }

      //directory and unexisting file are unexpected
      if(is_directory(file->file.m_info.header.type) || is_unexisting(file->file.m_info.header.type))
      {
         std::cout << "Unexpected file type" << std::endl;
         return -1;
      }
      //copy unencrypted files
      else if(is_unencrypted(file->file.m_info.header.type))
      {
         if(!filepath.copy_existing_file(titleIdPath, destTitleIdPath))
         {
            std::cout << "Failed to copy: " << filepath << std::endl;
            return -1;
         }
         else
         {
            std::cout << "Copied: " << filepath << std::endl;
         }
      }
      //decrypt encrypted files
      else if(is_encrypted(file->file.m_info.header.type))
      {
         if(decrypt_file(cryptops, iF00D, titleIdPath, destTitleIdPath, *file, filepath, klicensee, ngpfs, t) < 0)
         {
            std::cout << "Failed to decrypt: " << filepath << std::endl;
            return -1;
         }
         else
         {
            std::cout << "Decrypted: " << filepath << std::endl;
         }
      }
      else
      {
         std::cout << "Unexpected file type" << std::endl;
         return -1;
      }
   }   

   return 0;
}