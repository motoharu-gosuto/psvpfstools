#include "NodeIcvCalculator.h"

#include <string>
#include <vector>

#include "FilesDbParser.h"
#include "Utils.h"

#include <libcrypto/sha1.h>

unsigned char* c_node_icvs(unsigned char* raw_data, int order)
{
  int offset = 0x48 * order + 0x10 * order - 0x38;
  return raw_data + offset;
}

int icv_set_hmac_sw(unsigned char* iv, const unsigned char* key, unsigned char* input, int length)
{
  sha1_hmac(key, 0x14, input, length, iv);
  return 0;
}

int icv_contract_hmac(unsigned char* iv, const unsigned char* key, const unsigned char* base0_src, const unsigned char* base1_src)
{
  unsigned char base[0x28];
  memcpy(base, base0_src, 0x14);
  memcpy(base + 0x14, base1_src, 0x14);
  return icv_set_hmac_sw(iv, key, base, 0x28);
}

//should return page size
int node_size(int index)
{
  return 0x6C * index - 0x38;
}

//get order of the page (max number of hashes per page)
int order_max_avail(uint32_t pagesize)
{
  int index;
  //calculate max possible index until data size does not fit the page
  for(index = 1; pagesize > node_size(index); index++);
  //substract one entry if last entry overflows the page
  if(pagesize < node_size(index))
    index--;
  return index;
}

int calculate_node_icv(sce_ng_pfs_header_t& ngh, unsigned char* secret, sce_ng_pfs_block_header_t* node_header, unsigned char* raw_data, unsigned char* icv)
{
   int order = order_max_avail(ngh.pageSize); //get order of the page (max number of hashes per page)

   if(ngh.version == 5)
   {
      size_t dataSize = (0x6C * order - 0x3C); //should be page size - 4
      sha1_hmac(secret, 0x14, raw_data + 4, dataSize, icv);  
      return 0;
   }
   
   if(node_header == 0)
      return -1;

   uint32_t nEntries = node_header->nFiles;
   if (node_header->type > 0)
      nEntries++;

   memset(icv, 0, 0x14);

   for (int index = 0; index < nEntries; index++)
   {
      unsigned char* icvs_base = c_node_icvs(raw_data, order);
      icv_contract_hmac(icv, secret, icv, icvs_base + index * 0x14);
   }

   return 0;
}