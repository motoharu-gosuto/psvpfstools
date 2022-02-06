#include "F00DFileKeyEncryptor.h"

#include <boost/algorithm/string.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <fstream>

#include "Utils.h"

F00DFileKeyEncryptor::F00DFileKeyEncryptor(boost::filesystem::path filePath)
   : m_filePath(filePath), m_isCacheLoaded(false)
{
}

int F00DFileKeyEncryptor::load_cache_flat_file()
{
   if(!boost::filesystem::exists(m_filePath))
      return -1;

   std::ifstream input(m_filePath.generic_string().c_str());
   if(!input.is_open())
      return -1;

   std::string line;
   std::vector<std::string> tokens;
   while(std::getline(input, line))
   {
      //parse string - allow multiple split tokens
      tokens.clear();
      boost::split(tokens, line, boost::is_any_of(" \t,"));

      //there should be exactly three values - titleid, key, value
      if(tokens.size() != 3)
         return -1;

      //extract tokens
      std::string key = tokens.at(1);
      std::string value = tokens.at(2);
      
      // check key length to be 128 or 256 bit
      if(key.length() != 32 && key.length() != 64)
         return -1;

      //key size must equal value size
      if(key.length() != value.length())
         return -1;

      // do not allow duplicates
      auto kit = m_keyCache.find(key);
      if(kit != m_keyCache.end())
         return -1;

      m_keyCache.emplace(key, value);
   }

   return 0;
}

int F00DFileKeyEncryptor::load_cache_json_file()
{
   if(!boost::filesystem::exists(m_filePath))
      return -1;

   try
   {
      boost::property_tree::ptree pt;
      boost::property_tree::read_json(m_filePath.generic_string(), pt);

      for(auto& item : pt)
      {
         //parse entry
         std::string titleid = item.first;

         auto keych = item.second.get_child("key");
         auto valuech = item.second.get_child("value");

         std::string key = keych.get_value<std::string>();
         std::string value = valuech.get_value<std::string>();

         //check that values are not empty
         if(titleid.empty() || key.empty() || value.empty())
            return -1;

         // check key length to be 128 or 256 bit
         if(key.length() != 32 && key.length() != 64)
            return -1;

         //key size must equal value size
         if(key.length() != value.length())
            return -1;

         // do not allow duplicates
         auto kit = m_keyCache.find(key);
         if(kit != m_keyCache.end())
            return -1;

         m_keyCache.emplace(key, value);
      }
   }
   catch(std::exception& e)
   {
      return -1;
   }

   return 0;
}

int F00DFileKeyEncryptor::load_cache_file()
{
   if(m_filePath.extension() == ".txt")
      return load_cache_flat_file();
   else if(m_filePath.extension() == ".json")
      return load_cache_json_file();
   else
      return -1;
}

int F00DFileKeyEncryptor::encrypt_key(const unsigned char* key, int key_size, unsigned char* drv_key)
{
   if(key_size != 0x80 && 
      // key_size != 0xC0 && //TODO: need to implement padding
      key_size != 0x100)
      return -1;

   if(!m_isCacheLoaded)
   {
      if(load_cache_file() != 0)
         return -1;

      m_isCacheLoaded = true;
   }

   std::string keyStr = byte_array_to_string(key, key_size / 8);

   auto kit = m_keyCache.find(keyStr);
   if(kit == m_keyCache.end())
      return -1;
   
   std::uint32_t nbytes = key_size / 8;
   string_to_byte_array(kit->second, nbytes, drv_key);
   return 0;
}

void F00DFileKeyEncryptor::print_cache(std::ostream& os, std::string sep) const
{
   /*
   for(auto& item : m_keyCache)
   {
      os << item.first << sep << item.second << std::endl;
   }
   */
}
