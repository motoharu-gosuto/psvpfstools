#include "F00DUrlKeyEncryptor.h"

#include <stdio.h>
#include <curl/curl.h>
#include <iomanip>
#include <string>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/algorithm/string.hpp>

#include "Utils.h"

F00DUrlKeyEncryptor::F00DUrlKeyEncryptor(const std::string& F00D_url)
   : m_F00D_url(F00D_url)
{
}

std::string F00DUrlKeyEncryptor::create_url(unsigned const char* key, int key_size)
{
   std::stringstream ss;

   ss << m_F00D_url << "/?key=";

   int nbytes = key_size / 8;
   for(int i = 0; i < nbytes; i++)
   {
      ss << std::setfill('0') << std::setw(2) << std::hex << (int)key[i];
   }

   return ss.str();
}

size_t F00DUrlKeyEncryptor::write_callback(char* ptr, size_t size, size_t nmemb, void* userdata)
{
   size_t realsize = size * nmemb;

   F00DUrlKeyEncryptor* inst = (F00DUrlKeyEncryptor*)userdata;
   inst->m_response = std::string(ptr);

   return realsize;
}

int F00DUrlKeyEncryptor::execute_url(std::string url)
{
   CURL *curl;
   CURLcode res;

   curl = curl_easy_init();
   if(curl) 
   {
      struct curl_slist *headers=NULL; // init to NULL is important 
      headers = curl_slist_append(headers, "Accept: application/json");  
      headers = curl_slist_append(headers, "Content-Type: application/json");
      headers = curl_slist_append(headers, "charsets: utf-8"); 

      curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
      curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
      curl_easy_setopt(curl, CURLOPT_HTTPGET,1); 

      curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
      curl_easy_setopt(curl, CURLOPT_WRITEDATA, this);

      // Perform the request, res will get the return code
      res = curl_easy_perform(curl);

      //clean list
      curl_slist_free_all(headers);

      // Check for errors
      if(res != CURLE_OK)
      {
         //fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));

         //it is too time consuming to write a code to throw up an error code from all crypto functions
         //much easier to throw an exception
         throw std::runtime_error("Unable to get response from F00D service");
      }
 
      // always cleanup
      curl_easy_cleanup(curl);

      return 0;
   }

   return -1;
}

int F00DUrlKeyEncryptor::parse_key_base(unsigned const char* key, unsigned char* dest, int key_size, std::string jkey, std::string jdrv_key)
{
   std::uint32_t nbytes = key_size / 8;

   unsigned char key_check[0x20];
   string_to_byte_array(jkey, nbytes, key_check);
   
   if(memcmp(key, key_check, nbytes) != 0)
      return -1;

   string_to_byte_array(jdrv_key, nbytes, dest);

   m_keyCache.insert(std::make_pair(jkey, jdrv_key));

   return 0;
}

int F00DUrlKeyEncryptor::parse_key(unsigned const char* key, unsigned char* dest, int key_size)
{
   std::string json(m_response);
   boost::trim(json);

   std::stringstream ss;
   ss << json;

   boost::property_tree::ptree pt;
   boost::property_tree::read_json(ss, pt);

   std::string jkey = pt.get_child("key").data();
   std::string jdrv_key = pt.get_child("drv_key").data();

   return parse_key_base(key, dest, key_size, jkey, jdrv_key);
}

int F00DUrlKeyEncryptor::encrypt_key(unsigned const char* key, int key_size, unsigned char* drv_key)
{
   if(key_size != 0x80 && 
      // key_size != 0xC0 && //TODO: need to implement padding
      key_size != 0x100)
      return -1;

   std::string keyStr = byte_array_to_string(key, key_size / 8);

   auto kit = m_keyCache.find(keyStr);
   if(kit != m_keyCache.end())
   {
      std::uint32_t nbytes = key_size / 8;
      string_to_byte_array(kit->second, nbytes, drv_key);
      return 0;
   }
   else
   {
      std::string url = create_url(key, key_size);
      if(execute_url(url) < 0)
         return -1;

      if(parse_key(key, drv_key, key_size) < 0)
         return -1;

      return 0;
   }
}

void F00DUrlKeyEncryptor::print_cache(std::ostream& os, std::string sep) const
{
   for(auto& item : m_keyCache)
   {
      os << item.first << sep << item.second << std::endl;
   }
}