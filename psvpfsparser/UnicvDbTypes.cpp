#include "UnicvDbTypes.h"

#include "UnicvDbUtils.h"
#include "Utils.h"

bool sig_tbl_header_base_t::validate(scei_ftbl_t& fft, uint32_t sizeCheck) const
{
   if(m_header.binTreeSize != binTreeSize(0x14, fft.get_header()->get_binTreeNumMaxAvail()))
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

bool sig_tbl_header_base_t::read(std::ifstream& inputStream, scei_ftbl_t& fft, uint32_t sizeCheck, std::vector<std::vector<uint8_t> >& signatures)
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
   uint64_t dsize = cp % fft.get_header()->get_pageSize(); //calc size of data that was read
   int64_t tail = fft.get_header()->get_pageSize() - dsize; //calc size of tail data

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

bool sig_tbl_header_merlke_t::read(std::ifstream& inputStream, scei_ftbl_t& fft, uint32_t sizeCheck, std::vector<std::vector<uint8_t> >& signatures)
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

std::shared_ptr<scei_ftbl_base_t> magic_to_ftbl(std::string type)
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
