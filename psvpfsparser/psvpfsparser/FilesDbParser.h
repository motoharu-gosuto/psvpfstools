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

struct header_t
{
   uint8_t magic[8];
   uint32_t unk1;
   uint32_t unk2;
   uint32_t blockSize;
   uint32_t unk3; // this is probably related to number of blocks
   uint32_t unk4; // this is probably related to number of blocks
   uint32_t unk5;
   uint64_t unk6;
   uint32_t tailSize;
   uint32_t unk7;
   uint32_t unk8;
   uint32_t unk9;
   uint8_t data[0x3c8];
};

struct block_header_t
{
   uint32_t id; // looks like 0x02 for block with general files, 0x0d for block with deleted files
   uint32_t type;
   uint32_t nFiles;
   uint32_t unk1;
};

struct file_header_t
{
   uint32_t index; //parent index
   uint8_t fileName[68];
};

enum file_types : uint16_t
{
   unexisting = 0x00,
   normal_file = 0x01,
   directory = 0x8000,
   unencrypted_system_file = 0x4006,
   encrypted_system_file = 0x06
};

struct file_info_t
{
   uint32_t idx; // this file index
   file_types type;
   uint16_t unk1;
   uint32_t size;
   uint32_t unk2;
};

struct hash_header_t
{
   uint32_t unk1;
   uint32_t unk2;
   uint32_t unk3;
   uint32_t unk4;
};

struct hash_t
{
   uint8_t data[20];
};

struct block_t
{
   block_header_t header;
   std::vector<file_header_t> files;
   std::vector<file_info_t> infos;
   hash_header_t hash_header;
   std::vector<hash_t> hashes;
};

struct flat_block_t
{
   block_header_t header;
   file_header_t file;
   file_info_t info;
   hash_header_t hash_header;
   hash_t hash;
};

struct file_t
{
   boost::filesystem::path path;
   flat_block_t block;
};

#pragma pack(pop)

int parseAndFlattenFilesDb(std::string title_id_path);