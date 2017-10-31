#pragma once

#include <string>

class F00DKeyEncryptor
{
private:
   std::string m_response;

private:
   std::string create_url(unsigned const char* key, int key_size);

private:
   static size_t write_callback(char* ptr, size_t size, size_t nmemb, void* userdata);

   int execute_url(std::string url);

private:
   int string_to_byte_array(std::string str, int nBytes, unsigned char* dest);

   int parse_key(unsigned const char* key, unsigned char* dest, int key_size);

public:
   int encrypt_key(const unsigned char* key, int key_size, unsigned char* drv_key);
};
