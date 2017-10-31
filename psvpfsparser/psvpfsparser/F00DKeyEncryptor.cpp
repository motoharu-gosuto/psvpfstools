#include "F00DKeyEncryptor.h"

#include <stdio.h>
#include <curl/curl.h>
#include <iomanip>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/algorithm/string.hpp>

std::string F00DKeyEncryptor::create_url(unsigned const char* key, int key_size)
{
   std::stringstream ss;

   ss << DMAC5_URL << "/?key=";

   int nbytes = key_size / 8;
   for(int i = 0; i < nbytes; i++)
   {
      ss << std::setfill('0') << std::setw(2) << std::hex << (int)key[i];
   }

   return ss.str();
}

size_t F00DKeyEncryptor::write_callback(char* ptr, size_t size, size_t nmemb, void* userdata)
{
   size_t realsize = size * nmemb;

   F00DKeyEncryptor* inst = (F00DKeyEncryptor*)userdata;
   inst->m_response = std::string(ptr);

   return realsize;
}

int F00DKeyEncryptor::execute_url(std::string url)
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
         return -1;
      }
 
      // always cleanup
      curl_easy_cleanup(curl);

      return 0;
   }

   return -1;
}

int F00DKeyEncryptor::string_to_byte_array(std::string str, int nBytes, unsigned char* dest)
{
   for(int i = 0, j = 0 ; j < nBytes; i = i + 2, j++)
   {
      std::string byteString = str.substr(i, 2);
      unsigned char byte = (unsigned char)strtol(byteString.c_str(), NULL, 16);
      dest[j] = byte;
   }
   return 0;
}

int F00DKeyEncryptor::parse_key(unsigned const char* key, unsigned char* dest, int key_size)
{
   std::string json(m_response);
   boost::trim(json);

   std::stringstream ss;
   ss << json;

   boost::property_tree::ptree pt;
   boost::property_tree::read_json(ss, pt);

   std::string jkey = pt.get_child("key").data();
   std::string jdrv_key = pt.get_child("drv_key").data();

   int nbytes = key_size / 8;

   unsigned char key_check[0x20];
   string_to_byte_array(jkey, nbytes, key_check);
   
   if(memcmp(key, key_check, nbytes) != 0)
      return -1;

   string_to_byte_array(jdrv_key, nbytes, dest);

   return 0;
}

int F00DKeyEncryptor::encrypt_key(unsigned const char* key, int key_size, unsigned char* drv_key)
{
   if(key_size != 0x80 && key_size != 0xC0 && key_size != 0x100)
      return -1;

   std::string url = create_url(key, key_size);
   if(execute_url(url) < 0)
      return -1;

   if(parse_key(key, drv_key, key_size) < 0)
      return -1;

   return 0;
}