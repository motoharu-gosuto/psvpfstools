#pragma once

//very basics of the format can be found here
//http://www.vitadevwiki.com/index.php?title=Files.db

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <stdint.h>
#include <algorithm>
#include <map>
#include <iomanip>

#include <boost/filesystem.hpp>

#pragma pack(push, 1)

#define MAGIC_WORD "SCENGPFS"

#define MAX_FILES_IN_BLOCK 9

#define EXPECTED_BLOCK_SIZE 0x400

struct sce_ng_pfs_header_t
{
   uint8_t magic[8];
   uint32_t unk1;
   uint32_t unk2;
   uint32_t blockSize;
   uint32_t unk3; // this is probably related to number of blocks ?
   uint32_t unk4; // this is probably related to number of blocks ?
   uint32_t salt0; // first salt value used for key derrivation
   uint64_t unk6;
   uint32_t tailSize; // size of data after this header
   uint32_t unk7;
   uint32_t unk8;
   uint32_t unk9;
   uint8_t data0[0x14];
   uint8_t data1[0x14];
   uint8_t rsa_sig0[0x100];
   uint8_t rsa_sig1[0x100];
   uint8_t padding[0x1A0];
};

//still have to figure out
enum sce_ng_pfs_block_types : uint32_t
{
   regular = 0,
   unknown_block_type = 1 //still have to figure out
};

struct sce_ng_pfs_block_header_t
{
   uint32_t id; // this field is either flag or some number that can vary a lot 
                // int simple example looks like it is 0x02 for block with general files, 0x0d for block with deleted files
                // however in examples with many files - this can take lots of different values
   sce_ng_pfs_block_types type;
   uint32_t nFiles;
   uint32_t padding; // probably padding ? always 0
};

//there can be 9 files at max in one block
struct sce_ng_pfs_file_header_t
{
   uint32_t index; //parent index
   uint8_t fileName[68];
};

enum sce_ng_pfs_file_types : uint16_t
{
   unexisting = 0x00,
   normal_file = 0x01,
   directory = 0x8000,
   unencrypted_system_file = 0x4006,
   encrypted_system_file = 0x06
};

#define INVALID_FILE_INDEX 0xFFFFFFFF

struct sce_ng_pfs_file_info_t
{
   uint32_t idx; // this file index. can be INVALID_FILE_INDEX
   sce_ng_pfs_file_types type;
   uint16_t padding0; //probably padding ? always 0
   uint32_t size;
   uint32_t padding1; //probably padding ? always 0
};

struct sce_ng_pfs_hash_t
{
   uint8_t data[20];
};

struct sce_ng_pfs_block_t
{
   sce_ng_pfs_block_header_t header; //size = 16
   std::vector<sce_ng_pfs_file_header_t> files; // size = 72 * 9 = 648

   //infos may contain non INVALID_FILE_INDEX as last element
   //still dont know the purpose of this
   std::vector<sce_ng_pfs_file_info_t> infos; // size = 16 * 10 = 160
   std::vector<sce_ng_pfs_hash_t> hashes; // size = 20 * 10 = 200
};

struct sce_ng_pfs_flat_block_t
{
   sce_ng_pfs_block_header_t header;
   sce_ng_pfs_file_header_t file;
   sce_ng_pfs_file_info_t info;
   sce_ng_pfs_hash_t hash;

   int global_index;
};

struct sce_ng_pfs_file_t
{
   boost::filesystem::path path;
   sce_ng_pfs_flat_block_t file;
   std::vector<sce_ng_pfs_flat_block_t> dirs;
};

#pragma pack(pop)

int parseFilesDb(std::string title_id_path, std::vector<sce_ng_pfs_file_t>& filesResult);