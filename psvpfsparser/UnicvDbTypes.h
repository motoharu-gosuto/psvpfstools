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

//=================================================

struct scei_rodb_header_t
{
   uint8_t magic[8]; //SCEIRODB
   uint32_t version; // this is probably version? value is always 2
   uint32_t blockSize; //expected 0x400
   uint32_t unk2; //0xFFFFFFFF
   uint32_t unk3; //0xFFFFFFFF
   uint64_t dataSize; //size of data beginning from next chunk
};

class scei_rodb_header_proxy_t
{
private:
   scei_rodb_header_t m_header;

public:
   bool validate(uint64_t fileSize) const;

   bool read(std::ifstream& inputStream, uint64_t fileSize);

public:
   std::string get_magic() const
   {
      return std::string((char*)m_header.magic, 8);
   }

   uint32_t get_version() const
   {
      return m_header.version;
   }

   uint32_t get_blockSize() const
   {
      return m_header.blockSize;
   }
   
   uint64_t get_dataSize() const
   {
      return m_header.dataSize;
   }
};

//=================================================

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

//=================================================

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

class scei_ftbl_t;
class scei_ftbl_base_t;

class sig_tbl_header_base_t
{
protected:
   sig_tbl_header_t m_header;

public:
   virtual ~sig_tbl_header_base_t()
   {
   }
   
public:
   uint32_t get_binTreeSize() const
   {
      return m_header.binTreeSize;
   }

   uint32_t get_sigSize() const
   {
      return m_header.sigSize;
   }

   uint32_t get_nSignatures() const
   {
      return m_header.nSignatures;
   }

   uint32_t get_padding() const
   {
      return m_header.padding;
   }

public:
   bool validate(std::shared_ptr<scei_ftbl_base_t> fft, uint32_t sizeCheck) const;

   virtual bool read(std::ifstream& inputStream, std::shared_ptr<scei_ftbl_base_t> fft, uint32_t sizeCheck, std::vector<std::vector<uint8_t> >& signatures);

   virtual bool validate_tail(const std::vector<uint8_t>& data) const = 0;
};

class sig_tbl_header_normal_t : public sig_tbl_header_base_t
{
public:
   bool validate_tail(const std::vector<uint8_t>& data) const override;
};

class sig_tbl_header_merlke_t : public sig_tbl_header_base_t
{
public:
   bool read(std::ifstream& inputStream, std::shared_ptr<scei_ftbl_base_t> fft, uint32_t sizeCheck, std::vector<std::vector<uint8_t> >& signatures) override;

   bool validate_tail(const std::vector<uint8_t>& data) const override;
};

//this is a signature table structure - it contains header and list of signatures
//in more generic terms - this is also a data block of size 0x400
//signature table that is used to verify file hashes
//it can hold 0x32 signatures at max
//each signature corresponds to block in a real file. block should have size fileSectorSize (0x8000)
class sig_tbl_t
{
private:
   std::shared_ptr<sig_tbl_header_base_t> m_header;

public:
   sig_tbl_t(std::shared_ptr<sig_tbl_header_base_t> header)
      : m_header(header)
   {
   }

public:
   std::vector<std::vector<uint8_t> > m_signatures;

   std::shared_ptr<sig_tbl_header_base_t> get_header() const
   {
      return m_header;
   }

   bool read(std::ifstream& inputStream, std::shared_ptr<scei_ftbl_base_t> fft, uint32_t sizeCheck)
   {
      return m_header->read(inputStream, fft, sizeCheck, m_signatures);
   }
};

//=================================================

class scei_ftbl_header_base_t
{
public:
   virtual ~scei_ftbl_header_base_t()
   {
   }

public:
   virtual uint32_t get_numSectors() const = 0;

   virtual uint32_t get_numHashes() const = 0;

   virtual uint32_t get_fileSectorSize() const = 0;

   virtual const uint8_t* get_base_key() const = 0;

   virtual uint32_t get_binTreeNumMaxAvail() const = 0;

   virtual uint32_t get_pageSize() const = 0;

   virtual uint32_t get_version() const = 0;

   virtual std::string get_magic() const = 0;

public:
   virtual bool validate() const = 0;

   virtual bool read(std::ifstream& inputStream) = 0;
};

class scei_ftbl_header_proxy_t : public scei_ftbl_header_base_t
{
private:
   scei_ftbl_header_t m_header;

public:
   uint32_t get_numSectors() const override
   {
      return m_header.nSectors;
   }

   uint32_t get_numHashes() const override
   {
      return m_header.nSectors;
   }

   uint32_t get_fileSectorSize() const override
   {
      return m_header.fileSectorSize;
   }

   const uint8_t* get_base_key() const override
   {
      return m_header.base_key;
   }

   uint32_t get_binTreeNumMaxAvail() const override
   {
      return m_header.binTreeNumMaxAvail; 
   }

   uint32_t get_pageSize() const override
   {
      return m_header.pageSize; 
   }

   uint32_t get_version() const override
   {
      return m_header.version;
   }

   std::string get_magic() const override
   {
      return std::string((char*)m_header.magic, 8);
   }

public:
   bool validate() const override;

   bool read(std::ifstream& inputStream) override;
};

class scei_cvdb_header_proxy_t : public scei_ftbl_header_base_t
{
private:
   scei_cvdb_header_t m_header;

public:
   uint32_t get_numSectors() const override
   {
      return m_header.nSectors;
   }

   uint32_t get_numHashes() const override
   {
      //this is a formula for the number of hashes that will be calculated in merkle tree
      return m_header.nSectors * 2 - 1;
   }

   uint32_t get_fileSectorSize() const override
   {
      return m_header.fileSectorSize;
   }

   const uint8_t* get_base_key() const override
   {
      throw std::runtime_error("not implemented");
   }

   uint32_t get_binTreeNumMaxAvail() const override
   {
      return ICV_NUM_ENTRIES;
   }

   uint32_t get_pageSize() const override
   {
      return m_header.pageSize; 
   }

   uint32_t get_version() const override
   {
      return m_header.version;
   }

   std::string get_magic() const override
   {
      return std::string((char*)m_header.magic, 8);
   }

public:
   bool validate() const override;

   bool read(std::ifstream& inputStream) override;
};

class scei_null_header_proxy_t : public scei_ftbl_header_base_t
{
private:
   scei_null_header_t m_header;

public:
   uint32_t get_numSectors() const override
   {
      return 0;
   }

   uint32_t get_numHashes() const override
   {
      return 0;
   }

   uint32_t get_fileSectorSize() const override
   {
      return 0;
   }

   const uint8_t* get_base_key() const override
   {
      throw std::runtime_error("not implemented");
   }

   uint32_t get_binTreeNumMaxAvail() const override
   {
      throw std::runtime_error("not implemented");
   }

   uint32_t get_pageSize() const override
   {
      throw std::runtime_error("not implemented");
   }

   uint32_t get_version() const override
   {
      throw std::runtime_error("not implemented");
   }

   std::string get_magic() const override
   {
      return std::string((char*)m_header.magic, 8);
   }

public:
   bool validate() const override;

   bool read(std::ifstream& inputStream) override;
};
  
//this is a file table structure - it contais SCEIFTBL/SCEICVDB/SCEINULL header and list of file signature blocks
//in more generic terms - this is also a data block of size 0x400
//which is followed by signature blocks
class scei_ftbl_base_t : std::enable_shared_from_this<scei_ftbl_base_t>
{
protected:
   std::shared_ptr<scei_ftbl_header_base_t> m_header;

protected:
   uint32_t m_page;

public:
   std::vector<sig_tbl_t> m_blocks;

public:
   scei_ftbl_base_t(std::shared_ptr<scei_ftbl_header_base_t> header)
      : m_header(header),
        m_page(-1)
   {
   }

   virtual ~scei_ftbl_base_t()
   {
   }

public:
   std::shared_ptr<scei_ftbl_header_base_t> get_header() const
   {
      return m_header;
   }

public:
   uint32_t get_page() const
   {
      return m_page;
   }

public:
   virtual bool read(std::ifstream& inputStream, uint64_t& index);

protected:
   bool read_block(std::ifstream& inputStream, uint64_t& index, uint32_t sizeCheck);
};

class scei_ftbl_cvdb_proxy_t : public scei_ftbl_base_t
{
public:
   scei_ftbl_cvdb_proxy_t(std::shared_ptr<scei_ftbl_header_base_t> header)
      : scei_ftbl_base_t(header)
   {
   }

public:
   bool read(std::ifstream& inputStream, uint64_t& index) override;
};

//for now these types do not implement any additional logic that is different from base classes
//however clear separation in 3 different types is essential
class scei_ftbl_proxy_t : public scei_ftbl_cvdb_proxy_t
{
public:
   scei_ftbl_proxy_t(std::shared_ptr<scei_ftbl_header_base_t> header)
      : scei_ftbl_cvdb_proxy_t(header)
   {
   } 
};

class scei_cvdb_proxy_t : public scei_ftbl_cvdb_proxy_t
{
public:
   scei_cvdb_proxy_t(std::shared_ptr<scei_ftbl_header_base_t> header)
      : scei_ftbl_cvdb_proxy_t(header)
   {
   }
};

class scei_null_proxy_t : public scei_ftbl_base_t
{
public:
   scei_null_proxy_t(std::shared_ptr<scei_ftbl_header_base_t> header)
      : scei_ftbl_base_t(header)
   {
   }
};

//=================================================

class scei_db_base_t
{
public:
   std::vector<std::shared_ptr<scei_ftbl_base_t> > m_tables;

public:
   virtual ~scei_db_base_t()
   {
   }

public:
   virtual bool read(boost::filesystem::path filepath) = 0;

protected:
   bool read_table_item(std::ifstream& inputStream, uint64_t index);
};

//this is a root object for unicv.db - it contains SCEIRODB header and list of SCEIFTBL file table blocks
class scei_rodb_t : public scei_db_base_t
{
private:
   scei_rodb_header_proxy_t m_dbHeader;

public:
   bool read(boost::filesystem::path filepath);
};

//this is a root object for icv.db - it contains list of SCEICVDB and SCEINULL blocks. there is no additional header
class scei_icv_t : public scei_db_base_t
{
   bool read(boost::filesystem::path filepath);
};

#pragma pack(pop)

std::shared_ptr<sig_tbl_header_base_t> magic_to_sig_tbl(std::string type);

std::shared_ptr<scei_ftbl_header_base_t> magic_to_ftbl_header(std::string type);

std::shared_ptr<scei_ftbl_base_t> magic_to_ftbl(std::string type);
