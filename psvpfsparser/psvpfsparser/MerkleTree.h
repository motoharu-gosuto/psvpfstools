#pragma once

#include <stdint.h>
#include <vector>
#include <map>

typedef struct page_icv_data
{
   int64_t offset;
   uint32_t page;
   uint8_t icv[0x14];
};

int64_t page2off(uint32_t page, uint32_t block_size);

uint32_t off2page(int64_t offset, uint32_t block_size);

struct sce_ng_pfs_block_t;

bool validate_merkle_tree(int level, uint32_t page, const std::vector<sce_ng_pfs_block_t>& blocks, const std::multimap<uint32_t, page_icv_data>& page_icvs);