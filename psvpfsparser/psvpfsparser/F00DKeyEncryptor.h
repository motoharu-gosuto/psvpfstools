#pragma once

#include <stdint.h>

#include <string>
#include <map>

class F00DKeyEncryptor
{
private:
   std::string m_response;

   std::map<std::string, std::string> m_keyCache;

private:
   std::string create_url(unsigned const char* key, int key_size);

private:
   static size_t write_callback(char* ptr, size_t size, size_t nmemb, void* userdata);

   int execute_url(std::string url);

private:
   int parse_key_base(unsigned const char* key, unsigned char* dest, int key_size, std::string jkey, std::string jdrv_key);
   int parse_key(unsigned const char* key, unsigned char* dest, int key_size);

public:
   int encrypt_key(const unsigned char* key, int key_size, unsigned char* drv_key);
};

F00DKeyEncryptor* get_F00D_encryptor();