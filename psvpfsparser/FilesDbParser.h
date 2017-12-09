#pragma once

//very basics of the format can be found here
//http://www.vitadevwiki.com/index.php?title=Files.db

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstdint>
#include <algorithm>
#include <map>
#include <iomanip>

#include <boost/filesystem.hpp>

#pragma pack(push, 1)

#define MAGIC_WORD "SCENGPFS"

#define MAX_FILES_IN_BLOCK 9

#define EXPECTED_BLOCK_SIZE 0x400

#define FILES_EXPECTED_VERSION_3 3
#define FILES_EXPECTED_VERSION_4 4 //looks like files.db salt appeared in this version
#define FILES_EXPECTED_VERSION_5 5

#define FILES_GAME_TYPE 1 
#define FILES_TROPHY_SAVE_TYPE 2

struct sce_ng_pfs_header_t
{
   std::uint8_t magic[8];
   std::uint32_t version;
   std::uint16_t type; // 0x1 for games, 0x2 for trophy or savedata. probably type ?
   std::uint16_t unk21;
   std::uint32_t pageSize;
   std::uint32_t flags; // not sure but probably matches order value of the tree in btree_init
   std::uint32_t root_icv_page_number; // derived from off2pgn
   std::uint32_t files_salt; // first salt value used for key derrivation
   std::uint64_t unk6;
   std::uint32_t tailSize; // size of data after this header
   std::uint32_t unk7;
   std::uint32_t unk8;
   std::uint32_t unk9;
   std::uint8_t root_icv[0x14]; // 0x38 hmac-sha1 of (pageSize - 4) of page (pointed by root_icv_page_number) with secret derived from klicensee
   std::uint8_t header_sig[0x14]; // 0x4C hmac-sha1 of 0x16 bytes of header with secret derived from klicensee
   std::uint8_t rsa_sig0[0x100];
   std::uint8_t rsa_sig1[0x100];
   std::uint8_t padding[0x1A0];
};

//still have to figure out
enum sce_ng_pfs_block_types : std::uint32_t
{
   child = 0,
   root = 1 // if page number is -1 then root. otherwise - unknown
};

struct sce_ng_pfs_block_header_t
{
   std::uint32_t parent_page_number; 
   sce_ng_pfs_block_types type;
   std::uint32_t nFiles;
   std::uint32_t padding; // probably padding ? always 0
};

//there can be 9 files at max in one block
struct sce_ng_pfs_file_header_t
{
   std::uint32_t index; //parent index
   std::uint8_t fileName[68];
};

#define FILE_TYPE_FLAG_UNEXISTING   0x0000
#define FILE_TYPE_FLAG_NORMAL_FILE  0x0001
#define FILE_TYPE_FLAG_SYSTEM_FILE1 0x0002
#define FILE_TYPE_FLAG_SYSTEM_FILE2 0x0004
#define FILE_TYPE_FLAG_UNK00 0x0008
#define FILE_TYPE_FLAG_UNK01 0x0010
#define FILE_TYPE_FLAG_UNK02 0x0020
#define FILE_TYPE_FLAG_UNK03 0x0040
#define FILE_TYPE_FLAG_UNK04 0x0080
#define FILE_TYPE_FLAG_UNK05 0x0100
#define FILE_TYPE_FLAG_UNK06 0x0200
#define FILE_TYPE_FLAG_UNK07 0x0400
#define FILE_TYPE_FLAG_UNK08 0x0800
#define FILE_TYPE_FLAG_UNK09 0x1000
#define FILE_TYPE_FLAG_UNK10 0x2000
#define FILE_TYPE_FLAG_UNENCRYPTED 0x4000
#define FILE_TYPE_FLAG_NORMAL_DIR  0x8000

enum sce_ng_pfs_file_types : std::uint16_t
{
   unexisting =       FILE_TYPE_FLAG_UNEXISTING,  //(0x0000)
   normal_file =      FILE_TYPE_FLAG_NORMAL_FILE, //(0x0001)
   normal_directory = FILE_TYPE_FLAG_NORMAL_DIR,  //(0x8000)
   
   // directory that has size multiple of sector size (size of dir is usually 0) (file inside is padded with zeroes) ?
   unk_directory = FILE_TYPE_FLAG_NORMAL_DIR | FILE_TYPE_FLAG_SYSTEM_FILE1 | FILE_TYPE_FLAG_SYSTEM_FILE2, //(0x8006)

   unencrypted_system_file = FILE_TYPE_FLAG_UNENCRYPTED | FILE_TYPE_FLAG_SYSTEM_FILE1 | FILE_TYPE_FLAG_SYSTEM_FILE2, //(0x4006)
   encrypted_system_file = FILE_TYPE_FLAG_SYSTEM_FILE1 | FILE_TYPE_FLAG_SYSTEM_FILE2, //(0x0006)

   unk1 = FILE_TYPE_FLAG_UNENCRYPTED | FILE_TYPE_FLAG_SYSTEM_FILE1 | FILE_TYPE_FLAG_SYSTEM_FILE2 | FILE_TYPE_FLAG_NORMAL_FILE, //(0x4007)
   unk2 = FILE_TYPE_FLAG_SYSTEM_FILE1 | FILE_TYPE_FLAG_SYSTEM_FILE2 | FILE_TYPE_FLAG_NORMAL_FILE //(0x0007)
};

#define INVALID_FILE_INDEX 0xFFFFFFFF

struct sce_ng_pfs_file_info_t
{
   std::uint32_t idx; // this file index. can be INVALID_FILE_INDEX
   sce_ng_pfs_file_types type;
   std::uint16_t padding0; //probably padding ? always 0
   std::uint32_t size;
   std::uint32_t padding1; //probably padding ? always 0
};

struct sce_ng_pfs_hash_t
{
   std::uint8_t data[20];
};

struct sce_ng_pfs_block_t
{
   sce_ng_pfs_block_header_t header; //size = 16
   std::vector<sce_ng_pfs_file_header_t> files; // size = 72 * 9 = 648

   //infos may contain non INVALID_FILE_INDEX as last element
   //still dont know the purpose of this
   std::vector<sce_ng_pfs_file_info_t> infos; // size = 16 * 10 = 160
   std::vector<sce_ng_pfs_hash_t> hashes; // size = 20 * 10 = 200

   std::uint32_t page;
};

struct sce_ng_pfs_flat_block_t
{
   sce_ng_pfs_block_header_t header;
   sce_ng_pfs_file_header_t file;
   sce_ng_pfs_file_info_t info;
   sce_ng_pfs_hash_t hash;
};

struct sce_ng_pfs_file_t
{
   boost::filesystem::path path;
   sce_ng_pfs_flat_block_t file;
   std::vector<sce_ng_pfs_flat_block_t> dirs;
};

struct sce_ng_pfs_dir_t
{
   boost::filesystem::path path;
   sce_ng_pfs_flat_block_t dir;
   std::vector<sce_ng_pfs_flat_block_t> dirs;
};

#pragma pack(pop)

int parseFilesDb(unsigned char* klicensee, boost::filesystem::path titleIdPath, sce_ng_pfs_header_t& header, std::vector<sce_ng_pfs_file_t>& filesResult, std::vector<sce_ng_pfs_dir_t>& dirsResult);