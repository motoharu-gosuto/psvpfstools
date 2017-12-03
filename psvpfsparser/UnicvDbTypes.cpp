#include "UnicvDbTypes.h"

#include "UnicvDbUtils.h"

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