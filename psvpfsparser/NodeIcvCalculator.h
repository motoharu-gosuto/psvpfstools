#pragma once

struct sce_ng_pfs_header_t;
struct sce_ng_pfs_block_header_t;

int calculate_node_icv(sce_ng_pfs_header_t& ngh, unsigned char* secret, sce_ng_pfs_block_header_t* node_header, unsigned char* raw_data, unsigned char *icv);