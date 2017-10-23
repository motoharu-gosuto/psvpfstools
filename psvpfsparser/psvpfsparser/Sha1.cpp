#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <stdint.h>
#include <algorithm>
#include <map>
#include <iomanip>

//hash functions
//https://en.wikipedia.org/wiki/List_of_hash_functions

//using sha-1 from boost
//https://gist.github.com/jhasse/990731

#include <boost/uuid/sha1.hpp>

void display(char* hash)
{
   std::cout << std::hex;
   for(int i = 0; i < 20; ++i)
   {
      std::cout << ((hash[i] & 0x000000F0) >> 4) 
                <<  (hash[i] & 0x0000000F);
   } 
   std::cout << std::endl;
}

void sha1(std::string filePath)
{
   std::ifstream inputStream(filePath, std::ios::in | std::ios::binary);
   inputStream.seekg(0, std::ios::end);
   int64_t size = inputStream.tellg();
   inputStream.seekg(0, std::ios::beg);
   std::vector<uint8_t> data(size);
   inputStream.read((char*)data.data(), size);

   boost::uuids::detail::sha1 s;
	char hash[20];
	
	s.process_bytes(data.data(), data.size());
	unsigned int digest[5];
	s.get_digest(digest);
	for(int i = 0; i < 5; ++i)
	{
		const char* tmp = reinterpret_cast<char*>(digest);
		hash[i*4] = tmp[i*4+3];
		hash[i*4+1] = tmp[i*4+2];
		hash[i*4+2] = tmp[i*4+1];
		hash[i*4+3] = tmp[i*4];
	}
   display(hash);
}