#include "MerkleTree.h"

#include "FilesDbParser.h"

int64_t page2off(uint32_t page, uint32_t block_size)
{
   return page * block_size + block_size;
}

uint32_t off2page(int64_t offset, uint32_t block_size)
{
   return (offset - block_size) / block_size;
}

bool validate_merkle_tree(int level, uint32_t page, const std::vector<sce_ng_pfs_block_t>& blocks, const std::multimap<uint32_t, page_icv_data>& page_icvs)
{
   const sce_ng_pfs_block_t& current_block = blocks[page]; //it should be safe to use page directly as index

   if(current_block.page != page)
   {
      std::cout << "Invalid page" << std::endl;
      return false;
   }

   auto children = page_icvs.equal_range(page);
   for (auto it = children.first; it != children.second; it++)
   {
      std::cout << std::string(level, '.') << it->second.page;

      bool found = false;
      for(auto& hash : current_block.hashes)
      {
         if(memcmp(it->second.icv, hash.data, 0x14) == 0)
         {
            std::cout << " - OK" << std::endl;
            validate_merkle_tree(level + 1, it->second.page, blocks, page_icvs);
            found = true;
            break;
         }
      }

      if(!found)
      {
         std::cout << " - Hash does not match" << std::endl;
         return false;
      }
   }

   return true;
}