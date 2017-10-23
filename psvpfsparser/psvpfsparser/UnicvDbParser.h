#pragma once

#include <stdint.h>
#include <vector>

#include <boost/filesystem.hpp>

//i guess this is sony computer entertainment inc readonly database
#define DB_MAGIC_WORD "SCEIRODB"

#define FT_MAGIC_WORD "SCEIFTBL"

#define EXPECTED_BLOCK_SIZE 0x400
#define EXPECTED_CHUNK_SIZE 0x14

#pragma pack(push, 1)

struct db_header_t
{
   uint8_t magic[8]; //SCEIRODB
   uint32_t unk1; //version ? always 2
   uint32_t blockSize; //expected 0x400
   uint32_t unk2; //0xFFFFFFFF
   uint32_t unk3; //0xFFFFFFFF
   uint64_t dataSize; //size of data beginning from next chunk
};

//it looks like this file corresponds to files.db
//it has exactly same number of ft_header_t records with nChunks == 0 as there are directories
//and same number of ft_header_t records with nChunks != 0 as there are files
struct ft_header_t
{
   uint8_t magic[8]; //SCEIFTBL
   uint32_t unk1; //version ? always 2
   uint32_t blockSize; //expected 0x400
   uint32_t maxNChunks; //this can be max number of chunks in single dt_header_t?
   uint32_t nChunks; //this shows how many chunks of data in total will follow this block. one dt_header_t can contain 0x32 chunks at max
   
   //it looks like unicv.db file is definitely related to files.db file
   //not only nuber of ft_header_t records equals to number of files + directories
   //but also number of directories requals to number of ft_header_t records with nChunks == 0
   //now there is one more interesting fact.
   //take file sizes from files.db and sort them
   //then take all nChunks > 0 and sort them
   //this 2 collections correlate!
   //now if you divide file size by corresponding nChunks
   //you will notice that value is around 0x8000
   //which could mean that each chunk that goes after ft_header_t corresponds to 0x8000 byte block of the file
   //the only thing that I am currently unable to do is to match exactly file records from files.db to 
   //ft_header_t records from unicv.db
   uint32_t fileDbBlockSize; //I assume this is block size for files.db
   
   uint32_t unk6; //padding?

   //it looks like there is some 40 byte chunk sometimes. I can not determine any fields that indicates its presence
   //maybe these are two hmac-sha1 values ?
   //or some other keys. have no clue
   //these records are empty if ft_header_t corresponds to directory
   uint8_t data1[20];
   uint8_t data2[20];
};

//this is a data block - its size should be equal to blockSize
//data block consists from header and nChunks that follow it
//each chunk is a 20 byte vector - most likely icv
//if blocksize is 0x400 there can be maximum 0x32 chunks in single datablock
//however ft_header_t.nChunks indicates total number of chunks
//so if it is greater then 0x32 that means that multiple data blocks will follow ft_header_t
//ft_header_t.maxNChunks seems to be max number of chunks possible 
//for ft_header_t.blockSize but I am not sure
struct dt_header_t
{
   uint32_t payloadSize; // for blocksize 0x400 this would be 0x3f8 = sizeof(dt_header_t) + (0x32 * 0x14) : which are max number of chunks multiplied by size of chunk
   uint32_t chunkSize; //expected 0x14
   uint32_t nChunks; //number of chunks in this block
   uint32_t unk4; //padding ? always zero
};

struct files_dt_t
{
   dt_header_t dtHeader;
   std::vector<std::vector<uint8_t> > chunks;
};

struct files_ft_t
{
   ft_header_t ftHeader;
   std::vector<files_dt_t> blocks;
};

struct files_db_t
{
   db_header_t dbHeader;
   std::vector<files_ft_t> tables;
};

#pragma pack(pop)


bool parseFilesDb(boost::filesystem::path filepath, files_db_t& fdb);

void debugPrint(const files_db_t& fdb);