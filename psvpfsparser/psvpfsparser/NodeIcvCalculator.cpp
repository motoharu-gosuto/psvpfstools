#include "NodeIcvCalculator.h"

#include <string>
#include <vector>

#include "FilesDbParser.h"

#include "sha1.h"

void* _icv_init(unsigned char *icv)
{
  return memset(icv, 0, 0x14u);
}

const std::vector<sce_ng_pfs_hash_t>& _c_node_icvs(sce_ng_pfs_block_t& blockh, int order)
{
  //int offset = 0x48 * order + 0x10 * order - 0x38;
  //return (char *)node + offset;

   return blockh.hashes;
}

int _icv_set_hmac_sw(unsigned char *digest, unsigned char *key, unsigned char *input, int length)
{
  sha1_hmac((unsigned char*)key,0x14,(unsigned char*)input,length,(unsigned char*)digest);
  return 0;
}

int _icv_contract_hmac(unsigned char *digest, unsigned char *key, unsigned char *base0_src, const uint8_t *base1_src)
{
  unsigned char base[0x28];
  
  memcpy(base, base0_src, 0x14);
  memcpy(base + 0x14, base1_src, 0x14);
  return _icv_set_hmac_sw(digest, key, base, 0x28);
}

int _print_bytes(unsigned char* bytes, int length)
{
   for(int i = 0; i < length; i++)
   {
      std::cout << std::hex << std::setfill('0') << std::setw(2) << (0xFF & (int)bytes[i]);
   }
   std::cout << std::endl;
   return 0;
}

int _node_size(int index)
{
  return 0x6C * index - 0x38;
}

int _order_max_avail(uint32_t pagesize)
{
  signed int index; // [esp+4h] [ebp-4h]

  for ( index = 1; pagesize > _node_size(index); ++index )
    ;
  if ( pagesize < _node_size(index) )
    --index;
  return index;
}

int calculate_node_icv(unsigned char *secret, unsigned char *digest, sce_ng_pfs_header_t& ngh, sce_ng_pfs_block_t* nh, unsigned char* raw_data)
{
   int order = _order_max_avail(ngh.blockSize);

   if(ngh.version == 5)
   {
      
      size_t ilen = (0x6C * order - 0x3C); // = 3FC
      sha1_hmac(secret, 0x14, raw_data + 4, ilen, (unsigned char*)digest);
      
      return 0;
   }
   else
   {
      int result;
      signed int v6;
      int i;

      v6 = nh->header.nFiles;
      if ( nh->header.type )
         ++v6;

      _icv_init(digest);

      for ( i = 0; ; ++i )
      {
         result = i;
         if ( i >= v6 )
            break;

         const std::vector<sce_ng_pfs_hash_t>& icvs_ptr = _c_node_icvs(*nh, order);
         _icv_contract_hmac(digest, secret, digest, icvs_ptr[i].data);

         _print_bytes(digest, 0x14);
      }
      return result;
   }
}