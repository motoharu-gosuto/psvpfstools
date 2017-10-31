#pragma once

struct sce_ng_pfs_header_t;
struct sce_ng_pfs_block_t;

int calculate_node_icv(unsigned char *secret, unsigned char *digest, sce_ng_pfs_header_t& ngh, sce_ng_pfs_block_t* nh, unsigned char* raw_data);