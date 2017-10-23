#pragma once

#include <stdint.h>
#include <vector>

#include <boost/filesystem.hpp>

//i guess this is sony computer entertainment inc readonly database
#define DB_MAGIC_WORD "SCEIRODB"

#define FT_MAGIC_WORD "SCEIFTBL"

#define EXPECTED_BLOCK_SIZE 0x400
#define EXPECTED_SIGNATURE_SIZE 0x14
#define EXPECTED_FILE_SECTOR_SIZE 0x8000
#define EXPECTED_MAX_FILE_SECTORS 0x32

#pragma pack(push, 1)

struct db_header_t
{
   uint8_t magic[8]; //SCEIRODB
   uint32_t version; // this is probably version? value is always 2
   uint32_t blockSize; //expected 0x400
   uint32_t unk2; //0xFFFFFFFF
   uint32_t unk3; //0xFFFFFFFF
   uint64_t dataSize; //size of data beginning from next chunk
};

//this file table corresponds to files.db
//it has exactly same number of ft_header_t records with nSectors == 0 as there are directories
//and same number of ft_header_t records with nSectors != 0 as there are files
struct ft_header_t
{
   uint8_t magic[8]; //SCEIFTBL
   uint32_t version; // this is probably version? value is always 2
   uint32_t blockSize; //expected 0x400
   uint32_t maxNSectors; // this is probably max number of sectors in a single signatures_dt_t. expected value is 0x32
   uint32_t nSectors; //this shows how many sectors of data in total will follow this block. one signatures_dt_t can contain 0x32 sectors at max
                     //multiple signatures_dt_t group into single file

   //This is sector size for files.db
   uint32_t fileDbSectorSize; // expected 0x8000
   
   uint32_t padding; //this is probably padding? always zero

   //these records are empty if ft_header_t corresponds to directory
   uint8_t data1[20];
   uint8_t base_key[20]; // this is a base_key that is used to derive iv_xor_key - one of the keys required for decryption
};

//ft_header_t.nSectors indicates total number of sectors
//if it is greater then 0x32 that means that multiple signature blocks will follow
struct sig_header_t
{
   uint32_t tableSize; // for blocksize 0x400 this would be 0x3f8 = sizeof(sig_header_t) + (0x32 * 0x14) : which are maxNSectors * sigSize
                       // 8 bytes are unused
   uint32_t sigSize; //expected 0x14 - size of hmac-sha1 
   uint32_t nSignatures; //number of chunks in this block
   uint32_t padding; //most likely padding ? always zero
};

//this is a signature table structure - it contains header and list of signatures
//in more generic terms - this is also a data block of size 0x400
//signature table that is used to verify file hashes
//it can hold 0x32 signatures at max
//each signature corresponds to block in a real file. block should have size fileDbSectorSize (0x8000)
struct signatures_dt_t
{
   sig_header_t dtHeader;
   std::vector<std::vector<uint8_t> > signatures;
};

//this is a file table structure - it contais SCEIFTBL header and list of file signature blocks
//in more generic terms - this is also a data block of size 0x400
//which is followed by signature blocks
struct files_ft_t
{
   ft_header_t ftHeader;
   std::vector<signatures_dt_t> blocks;
};

//this is a root structure - it contains SCEIRODB header and list of SCEIFTBL file table blocks
struct files_db_t
{
   db_header_t dbHeader;
   std::vector<files_ft_t> tables;
};

#pragma pack(pop)

bool parseUnicvDb(boost::filesystem::path filepath, files_db_t& fdb);