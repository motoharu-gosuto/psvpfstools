#pragma once

#include <stdint.h>
#include <vector>
#include <set>

#include <boost/filesystem.hpp>
#include <boost/range/adaptor/reversed.hpp>
#include <boost/algorithm/string/predicate.hpp>

bool isZeroVector(std::vector<uint8_t>& data);

template<typename T>
bool isZeroVector(T begin, T end)
{
   for(T it = begin; it != end; ++it)
   {
      if((*it) != 0)
         return false;
   }
   return true;
}

int string_to_byte_array(std::string str, int nBytes, unsigned char* dest);

int print_bytes(const unsigned char* bytes, int length);

void getFileListNoPfs(boost::filesystem::path path, std::set<std::string>& files, std::set<std::string>& directories);