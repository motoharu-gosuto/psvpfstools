#pragma once

#include <stdint.h>
#include <vector>

#include <boost/filesystem.hpp>

//i guess this is sony computer entertainment inc readonly database
#define DB_MAGIC_WORD "SCEIRODB"

#define FT_MAGIC_WORD "SCEIFTBL"

#define CV_DB_MAGIC_WORD "SCEICVDB"

#define NULL_MAGIC_WORD "SCEINULL"

#define EXPECTED_PAGE_SIZE 0x400
#define EXPECTED_SIGNATURE_SIZE 0x14
#define EXPECTED_FILE_SECTOR_SIZE 0x8000

#define UNICV_EXPECTED_VERSION_1 1
#define UNICV_EXPECTED_VERSION_2 2

#define ICV_EXPECTED_VERSION_2 2

#define NULL_EXPECTED_VERSION 1

#define ICV_NUM_ENTRIES 0x2D

#pragma pack(push, 1)

struct scei_rodb_header_t
{
   uint8_t magic[8]; //SCEIRODB
   uint32_t version; // this is probably version? value is always 2
   uint32_t blockSize; //expected 0x400
   uint32_t unk2; //0xFFFFFFFF
   uint32_t unk3; //0xFFFFFFFF
   uint64_t dataSize; //size of data beginning from next chunk
};

enum cv_entry_type
{
   cv_none = 0,
   ftbl = 1,
   cvdb = 2,
   cv_null = 3,
};

//this file table corresponds to files.db
//it has exactly same number of scei_ftbl_header_t records with nSectors == 0 as there are directories
//and same number of scei_ftbl_header_t records with nSectors != 0 as there are files
struct scei_ftbl_header_t
{
   uint8_t magic[8]; //SCEIFTBL
   uint32_t version; // this is probably version? value is always 2
   uint32_t pageSize; //expected 0x400
   uint32_t binTreeNumMaxAvail; // this is probably max number of sectors in a single sig_tbl_t. expected value is 0x32
   uint32_t nSectors; //this shows how many sectors of data in total will follow this block. one sig_tbl_t can contain 0x32 sectors at max
                     //multiple sig_tbl_t group into single file

   //This is sector size for files.db
   uint32_t fileSectorSize; // expected 0x8000
   
   uint32_t padding; //this is probably padding? always zero

   //these records are empty if scei_ftbl_header_t corresponds to directory
   uint8_t data1[20];
   uint8_t base_key[20]; // this is a base_key that is used to derive iv_xor_key - one of the keys required for decryption
};

struct scei_cvdb_header_t
{
   uint8_t magic[8]; //SCEICVDB
   uint32_t version; // this is probably version? value is always 2
   uint32_t fileSectorSize;
   uint32_t pageSize; //expected 0x400
   uint32_t padding;
   uint32_t unk0; //0xFFFFFFFF
   uint32_t unk1; //0xFFFFFFFF
   uint64_t dataSize; // from next chunk maybe? or block size
   uint32_t nSectors;
   uint8_t data1[20];
};

struct scei_null_header_t
{
   uint8_t magic[8]; //SCEINULL
   uint32_t version; // 1
   uint32_t unk1;
   uint32_t unk2;
   uint32_t unk3;
};

//scei_ftbl_header_t.nSectors indicates total number of sectors
//if it is greater then 0x32 that means that multiple signature blocks will follow
struct sig_tbl_header_t
{
   uint32_t binTreeSize; // for unicv.db for blocksize 0x400 this would be 0x3f8 = sizeof(sig_tbl_header_t) + (0x32 * 0x14) : which are maxNSectors * sigSize (0x8 bytes are unused)
                         // for icv.db for blocksize 0x400 this would be 0x394 = sizeof(sig_icv_tbl_header_t) + (0x2D * 0x14) : which are 2D * sigSize (0x6C bytes are unused)
   uint32_t sigSize; //expected 0x14 - size of hmac-sha1 
   uint32_t nSignatures; //number of chunks in this block
   uint32_t padding; //most likely padding ? always zero
};

//this is a signature table structure - it contains header and list of signatures
//in more generic terms - this is also a data block of size 0x400
//signature table that is used to verify file hashes
//it can hold 0x32 signatures at max
//each signature corresponds to block in a real file. block should have size fileSectorSize (0x8000)
struct sig_tbl_t
{
   sig_tbl_header_t dtHeader;
   std::vector<std::vector<uint8_t> > signatures;
};

bool validate_ftbl_header(scei_ftbl_header_t& header);
bool validate_cvdb_header(scei_cvdb_header_t& header);
bool validate_null_header(scei_null_header_t& header);

//this is a file table structure - it contais SCEIFTBL header and list of file signature blocks
//in more generic terms - this is also a data block of size 0x400
//which is followed by signature blocks
struct scei_ftbl_t
{
public:
   cv_entry_type m_type;

private:
   scei_ftbl_header_t m_ftHeader;
   scei_cvdb_header_t m_cvHeader;
   scei_null_header_t m_nullHeader;

public:
   std::vector<sig_tbl_t> m_blocks;

   uint32_t m_page;

public:
   scei_ftbl_t()
      : m_page(-1)
   {
   }

public:
   char* header_raw()
   {
      switch(m_type)
      {
      case cv_entry_type::ftbl:
         return (char*)&m_ftHeader; 
      case cv_entry_type::cvdb:
         return (char*)&m_cvHeader;
      case cv_entry_type::cv_null:
         return (char*)&m_nullHeader;
      default:
         throw std::runtime_error("wrong cv_entry_type");
      }
   }

   uint32_t header_raw_size()
   {
      switch(m_type)
      {
      case cv_entry_type::ftbl:
         return sizeof(scei_ftbl_header_t);
      case cv_entry_type::cvdb:
         return sizeof(scei_cvdb_header_t);
      case cv_entry_type::cv_null:
         return sizeof(scei_null_header_t);
      default:
         throw std::runtime_error("wrong cv_entry_type");
      }
   }

   uint32_t get_nSectors()
   {
      switch(m_type)
      {
      case cv_entry_type::ftbl:
         return m_ftHeader.nSectors; 
      case cv_entry_type::cvdb:
         return m_cvHeader.nSectors * 2 - 1; //why is this strange formula?
      case cv_entry_type::cv_null:
         return 0;
      default:
         throw std::runtime_error("wrong cv_entry_type");
      }
   }

   uint32_t get_fileSectorSize()
   {
      switch(m_type)
      {
      case cv_entry_type::ftbl:
         return m_ftHeader.fileSectorSize; 
      case cv_entry_type::cvdb:
         return m_cvHeader.fileSectorSize;
      case cv_entry_type::cv_null:
         return EXPECTED_FILE_SECTOR_SIZE;
      default:
         throw std::runtime_error("wrong cv_entry_type");
      }
   }

   uint8_t* get_base_key()
   {
      switch(m_type)
      {
      case cv_entry_type::ftbl:
         return m_ftHeader.base_key; 
      case cv_entry_type::cvdb:
         throw std::runtime_error("wrong cv_entry_type");
      case cv_entry_type::cv_null:
         throw std::runtime_error("wrong cv_entry_type");
      default:
         throw std::runtime_error("wrong cv_entry_type");
      }
   }

   uint32_t get_binTreeNumMaxAvail()
   {
      switch(m_type)
      {
      case cv_entry_type::ftbl:
         return m_ftHeader.binTreeNumMaxAvail; 
      case cv_entry_type::cvdb:
         return ICV_NUM_ENTRIES;
      case cv_entry_type::cv_null:
         throw std::runtime_error("wrong cv_entry_type");
      default:
         throw std::runtime_error("wrong cv_entry_type");
      }
   }

   uint32_t get_pageSize()
   {
      switch(m_type)
      {
      case cv_entry_type::ftbl:
         return m_ftHeader.pageSize; 
      case cv_entry_type::cvdb:
         return m_cvHeader.pageSize;
      case cv_entry_type::cv_null:
         throw std::runtime_error("wrong cv_entry_type");
      default:
         throw std::runtime_error("wrong cv_entry_type");
      }
   }

   uint32_t get_version()
   {
      switch(m_type)
      {
      case cv_entry_type::ftbl:
         return m_ftHeader.version; 
      case cv_entry_type::cvdb:
         return m_cvHeader.version;
      case cv_entry_type::cv_null:
         throw std::runtime_error("wrong cv_entry_type");
      default:
         throw std::runtime_error("wrong cv_entry_type");
      }
   }

public:

   bool validate()
   {
      switch(m_type)
      {
      case cv_entry_type::ftbl:
         return validate_ftbl_header(m_ftHeader);
      case cv_entry_type::cvdb:
         return validate_cvdb_header(m_cvHeader);
      case cv_entry_type::cv_null:
         return validate_null_header(m_nullHeader);
      default:
         throw std::runtime_error("wrong cv_entry_type");
      }
   }
};

//this is a root structure - it contains SCEIRODB header and list of SCEIFTBL file table blocks
struct scei_rodb_t
{
   scei_rodb_header_t m_dbHeader;
   std::vector<scei_ftbl_t> tables;
};

#pragma pack(pop)

int parseUnicvDb(boost::filesystem::path titleIdPath, scei_rodb_t& fdb);