#include "UnicvDbTypes.h"

#include "UnicvDbUtils.h"
#include "Utils.h"
#include "MerkleTree.h"

bool scei_rodb_header_proxy_t::validate(uint64_t fileSize) const
{
   //check file size field
   if(fileSize != (m_header.dataSize + m_header.blockSize)) //do not forget to count header
   {
      std::cout << "Incorrect block size or data size" << std::endl;
      return false;
   }

   //check magic word
   if(std::string((const char*)m_header.magic, 8) != DB_MAGIC_WORD)
   {
      std::cout << "Invalid magic word" << std::endl;
      return false;
   }

   //check version
   if(m_header.version != UNICV_EXPECTED_VERSION_1 && m_header.version != UNICV_EXPECTED_VERSION_2)
   {
      std::cout << "Unexpected version" << std::endl;
      return false;
   }

   if(m_header.unk2 != 0xFFFFFFFF)
   {
      std::cout << "Unexpected unk2" << std::endl;
      return false;
   }

   if(m_header.unk3 != 0xFFFFFFFF)
   {
      std::cout << "Unexpected unk3" << std::endl;
      return false;
   }

   //debug check only for now to see if there are any other sizes
   if(m_header.blockSize != EXPECTED_PAGE_SIZE)
   {
      std::cout << "Unexpected page size" << std::endl;
      return false;
   }

   return true;
}

bool scei_rodb_header_proxy_t::read(std::ifstream& inputStream, uint64_t fileSize)
{
   //read header
   inputStream.read((char*)&m_header, sizeof(scei_rodb_header_t));

   if(!validate(fileSize))
      return false;

   inputStream.seekg(m_header.blockSize, std::ios::beg); //skip header

   return true;
}

//============

bool sig_tbl_header_base_t::validate(std::shared_ptr<scei_ftbl_base_t> fft, uint32_t sizeCheck) const
{
   if(m_header.binTreeSize != binTreeSize(0x14, fft->get_header()->get_binTreeNumMaxAvail()))
   {
      std::cout << "Unexpected tableSize" << std::endl;
      return false;
   }

   //check to see if there are any other sizes
   if(m_header.sigSize != EXPECTED_SIGNATURE_SIZE)
   {
      std::cout << "Unexpected chunk size" << std::endl;
      return false;
   }

   //check padding
   if(m_header.padding != 0)
   {
      std::cout << "Unexpected data instead of padding" << std::endl;
      return false;
   }

   //this check is usefull for validating file structure
   if(m_header.nSignatures != sizeCheck)
   {
      std::cout << "unexpected number of chunks" << std::endl;
      return false;
   }

   return true;
}

bool sig_tbl_header_base_t::read(std::ifstream& inputStream, std::shared_ptr<scei_ftbl_base_t> fft, uint32_t sizeCheck, std::vector<std::vector<uint8_t> >& signatures)
{
   //read header
   inputStream.read((char*)&m_header, sizeof(sig_tbl_header_t));
   
   //validate header
   if(!validate(fft, sizeCheck))
      return false;

   //read signatures
   for(uint32_t c = 0; c < m_header.nSignatures; c++)
   {
      signatures.push_back(std::vector<uint8_t>());
      std::vector<uint8_t>& dte = signatures.back();
      dte.resize(m_header.sigSize);
      inputStream.read((char*)dte.data(), m_header.sigSize);
   }

   //calculate size of tail data - this data should be zero padding
   //instead of skipping it is validated here that it contains only zeroes
   uint64_t cp = inputStream.tellg();
   uint64_t dsize = cp % fft->get_header()->get_pageSize(); //calc size of data that was read
   int64_t tail = fft->get_header()->get_pageSize() - dsize; //calc size of tail data

   //read tail data
   std::vector<uint8_t> data(tail);
   inputStream.read((char*)data.data(), tail);

   //fast way would be to use seek
   //inputStream.seekg(tail, std::ios::cur);

   //validate tail in specific class
   return validate_tail(data);
}


bool sig_tbl_header_normal_t::validate_tail(const std::vector<uint8_t>& data) const
{
   //validate tail data
   if(!isZeroVector(data))
   {
      std::cout << "Unexpected data instead of padding" << std::endl;
      return false;
   }

   return true;
}

bool sig_tbl_header_merlke_t::read(std::ifstream& inputStream, std::shared_ptr<scei_ftbl_base_t> fft, uint32_t sizeCheck, std::vector<std::vector<uint8_t> >& signatures)
{
   //read weird 0x10 byte zero header which makes the data not being aligned on page boder
   unsigned char zero_header[0x10];
   inputStream.read((char*)zero_header, 0x10);
   if(!isZeroVector(zero_header, zero_header + 0x10))
   {
      std::cout << "Invalid zero vector" << std::endl;
      return false;
   }

   return sig_tbl_header_base_t::read(inputStream, fft, sizeCheck, signatures);
}

bool sig_tbl_header_merlke_t::validate_tail(const std::vector<uint8_t>& data) const
{
   //TODO: implement proper validation of 0xFFFFFFFF field
   throw std::runtime_error("not implemented");
}

//===========

bool scei_ftbl_header_proxy_t::validate() const
{
   //check that block size is expected
   //this will allow to fail if there are any other unexpected block sizes
   if(m_header.pageSize != EXPECTED_PAGE_SIZE)
   {
      std::cout << "Unexpected block size" << std::endl;
      return false;
   }

   //check magic word
   if(std::string((const char*)m_header.magic, 8) != FT_MAGIC_WORD)
   {
      std::cout << "Invalid magic word" << std::endl;
      return false;
   }

   //check version
   if(m_header.version != UNICV_EXPECTED_VERSION_1 && m_header.version != UNICV_EXPECTED_VERSION_2)
   {
      std::cout << "Unexpected version" << std::endl;
      return false;
   }

   //check maxNSectors
   if(m_header.binTreeNumMaxAvail != binTreeNumMaxAvail(0x14, m_header.pageSize))
   {
      std::cout << "Unexpected binTreeNumMaxAvail" << std::endl;
      return false;
   }

   //check file sector size
   if(m_header.fileSectorSize != EXPECTED_FILE_SECTOR_SIZE)
   {
      std::cout << "Unexpected fileSectorSize" << std::endl;
      return false;
   }

   //check padding
   if(m_header.padding != 0)
   {
      std::cout << "Unexpected padding" << std::endl;
      return false;
   }

   return true;
}

bool scei_ftbl_header_proxy_t::read(std::ifstream& inputStream)
{
   inputStream.read((char*)&m_header, sizeof(scei_ftbl_header_t));
   return true;
}


bool scei_cvdb_header_proxy_t::validate() const
{
   if(m_header.pageSize != EXPECTED_PAGE_SIZE)
   {
      std::cout << "Unexpected block size" << std::endl;
      return false;
   }

   if(std::string((const char*)m_header.magic, 8) != CV_DB_MAGIC_WORD)
   {
      std::cout << "Invalid magic word" << std::endl;
      return false;
   }

   if(m_header.version != ICV_EXPECTED_VERSION_2)
   {
      std::cout << "Unexpected version" << std::endl;
      return false;
   }

   if(m_header.fileSectorSize != EXPECTED_FILE_SECTOR_SIZE)
   {
      std::cout << "Unexpected fileSectorSize" << std::endl;
      return false;
   }   

   //TODO: maybe should check m_header.dataSize somehow?

   if(m_header.unk0 != 0xFFFFFFFF)
   {
      std::cout << "Unexpected unk2" << std::endl;
      return false;
   }

   if(m_header.unk1 != 0xFFFFFFFF)
   {
      std::cout << "Unexpected unk3" << std::endl;
      return false;
   }

   if(m_header.padding != 0)
   {
      std::cout << "Unexpected padding" << std::endl;
      return false;
   }

   return true;
}

bool scei_cvdb_header_proxy_t::read(std::ifstream& inputStream)
{
   inputStream.read((char*)&m_header, sizeof(scei_cvdb_header_t));
   return true;
}


bool scei_null_header_proxy_t::validate() const
{
   if(std::string((const char*)m_header.magic, 8) != NULL_MAGIC_WORD)
   {
      std::cout << "Invalid magic word" << std::endl;
      return false;
   }

   if(m_header.version != NULL_EXPECTED_VERSION)
   {
      std::cout << "Unexpected version" << std::endl;
      return false;
   }

   if(m_header.unk1 != 0)
   {
      std::cout << "Unexpected unk1" << std::endl;
      return false;
   }

   if(m_header.unk2 != 0)
   {
      std::cout << "Unexpected unk2" << std::endl;
      return false;
   }

   if(m_header.unk3 != 0)
   {
      std::cout << "Unexpected unk3" << std::endl;
      return false;
   }

   return true;
}

bool scei_null_header_proxy_t::read(std::ifstream& inputStream)
{
   inputStream.read((char*)&m_header, sizeof(scei_null_header_t));
   return true;
}

//===========

std::shared_ptr<sig_tbl_header_base_t> magic_to_sig_tbl(std::string type)
{
   if(type == FT_MAGIC_WORD)
      return std::make_shared<sig_tbl_header_normal_t>();
   else if(type == CV_DB_MAGIC_WORD)
      return std::make_shared<sig_tbl_header_merlke_t>();
   else if(type == NULL_MAGIC_WORD)
      throw std::runtime_error("wrong magic");
   else
      throw std::runtime_error("wrong magic");
}

std::shared_ptr<scei_ftbl_header_base_t> magic_to_ftbl_header(std::string type)
{
   if(type == FT_MAGIC_WORD)
      return std::make_shared<scei_ftbl_header_proxy_t>();
   else if(type == CV_DB_MAGIC_WORD)
      return std::make_shared<scei_cvdb_header_proxy_t>();
   else if(type == NULL_MAGIC_WORD)
      return std::make_shared<scei_null_header_proxy_t>();
   else
      throw std::runtime_error("wrong magic");
}

std::shared_ptr<scei_ftbl_base_t> magic_to_ftbl(std::string type)
{
   if(type == FT_MAGIC_WORD)
      return std::make_shared<scei_ftbl_proxy_t>(magic_to_ftbl_header(type));
   else if(type == CV_DB_MAGIC_WORD)
      return std::make_shared<scei_cvdb_proxy_t>(magic_to_ftbl_header(type));
   else if(type == NULL_MAGIC_WORD)
      return std::make_shared<scei_null_proxy_t>(magic_to_ftbl_header(type));
   else
      throw std::runtime_error("wrong magic");
}

//===========

bool scei_ftbl_base_t::read(std::ifstream& inputStream, uint64_t& index)
{
   //read header
   if(!m_header->read(inputStream))
      return false;

   //validate header
   if(!m_header->validate())
      return false;

   return true;
}

bool scei_ftbl_base_t::read_block(std::ifstream& inputStream, uint64_t& index, uint32_t sizeCheck)
{
   //create new signature block
   m_blocks.push_back(sig_tbl_t(magic_to_sig_tbl(m_header->get_magic())));
   sig_tbl_t& fdt = m_blocks.back();

   //read and valiate signature block
   if(!fdt.read(inputStream, shared_from_this(), sizeCheck))
      return false;

   index++;

   return true;
}

bool scei_ftbl_cvdb_proxy_t::read(std::ifstream& inputStream, uint64_t& index)
{
   int64_t currentBlockPos = inputStream.tellg();
   
   if(!scei_ftbl_base_t::read(inputStream, index))
      return false;

   m_page = off2page_unicv(currentBlockPos, m_header->get_pageSize());

   //calculate size of tail data - this data should be zero padding
   //instead of skipping it is validated here that it contains only zeroes
   uint64_t cp = inputStream.tellg(); //get current pos
   uint64_t dsize = cp % m_header->get_pageSize(); //calc size of data that was read
   int64_t tail = m_header->get_pageSize() - dsize; //calc size of tail data

   //read tail
   std::vector<uint8_t> tailData(tail);
   inputStream.read((char*)tailData.data(), tail);

   //validate tail
   if(!isZeroVector(tailData))
   {
      std::cout << "Unexpected data instead of padding" << std::endl;
      return false;
   }

   //fast way would be to use seek
   //inputStream.seekg(tail, std::ios::cur);

   //check if there are any data blocks after current entry
   if(m_header->get_numSectors() == 0)
      return true;

   //check if there is single block read required or multiple
   if(m_header->get_numHashes() < m_header->get_binTreeNumMaxAvail())
   {
      return read_block(inputStream, index, m_header->get_numHashes());
   }
   else
   {
      uint32_t nDataBlocks = m_header->get_numHashes() / m_header->get_binTreeNumMaxAvail();
      uint32_t nDataTail = m_header->get_numHashes() % m_header->get_binTreeNumMaxAvail();

      for(uint32_t dbi = 0; dbi < nDataBlocks; dbi++)
      {
         if(!read_block(inputStream, index, m_header->get_binTreeNumMaxAvail()))
            return false;
      }

      if(nDataTail > 0)
      {
         if(!read_block(inputStream, index, nDataTail))
            return false;
      }

      return true;
   }
}

//===========

bool scei_db_base_t::read_table_item(std::ifstream& inputStream, uint64_t index)
{
   uint8_t magic[8];
   inputStream.read((char*)magic, sizeof(magic));
   inputStream.seekg(0, std::ios::beg);

   m_tables.push_back(magic_to_ftbl(std::string((char*)magic, sizeof(magic))));
   std::shared_ptr<scei_ftbl_base_t>& fft = m_tables.back();

   if(!fft->read(inputStream, index))
      return false;

   return true;
}

bool scei_rodb_t::read(boost::filesystem::path filepath)
{
   std::ifstream inputStream(filepath.generic_string().c_str(), std::ios::in | std::ios::binary);

   if(!inputStream.is_open())
   {
      std::cout << "failed to open unicv.db file" << std::endl;
      return false;
   }

   //get stream size
   inputStream.seekg(0, std::ios::end);
   uint64_t fileSize = inputStream.tellg();
   inputStream.seekg(0, std::ios::beg);
   
   //read header
   if(!m_dbHeader.read(inputStream, fileSize))
      return false;
   
   //it looks like unicv file is split into groups of SCEIFTBL chunks (blocks)
   //where each group corresponds to file or directory
   //however there is no obvious way to determine number of chunks in each group

   //the only way is to calculate total number of chunks (blocks)
   //and read them as stream splitting it into groups in the process
   
   uint64_t nBlocks = m_dbHeader.get_dataSize() / m_dbHeader.get_blockSize();
   uint64_t tailSize = m_dbHeader.get_dataSize() % m_dbHeader.get_blockSize();

   //check tail size just in case
   if(tailSize > 0)
   {
      std::cout << "Block misalign" << std::endl;
      return false;
   }

   std::cout << "Total blocks: " << std::dec << nBlocks << std::endl;

   //read all blocks
   for(uint64_t index = 0; index < nBlocks; index++)
   {
      //read single block
      if(!read_table_item(inputStream, index))
         return false;
   }

   //check that there is no data left
   uint64_t endp = inputStream.tellg();
   if(fileSize != endp)
   {
      std::cout << "Data misalign" << std::endl;
      return false;
   }

   return true;
}

bool scei_icv_t::read(boost::filesystem::path filepath)
{
   uint64_t index = 0;
   for(auto& entry : boost::make_iterator_range(boost::filesystem::directory_iterator(filepath), boost::filesystem::directory_iterator()))
   {
      std::ifstream inputStream(entry.path().generic_string().c_str(), std::ios::in | std::ios::binary);

      //read single block
      if(!read_table_item(inputStream, index))
         return false;
   }
   return true;
}