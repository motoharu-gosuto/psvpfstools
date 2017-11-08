#include <stdint.h>

#include <iomanip>
#include <vector>
#include <string>
#include <iostream>
#include <set>

#include <boost/filesystem.hpp>
#include <boost/range/adaptor/reversed.hpp>
#include <boost/algorithm/string/predicate.hpp>

#include "Utils.h"

bool isZeroVector(std::vector<uint8_t>& data)
{
   return isZeroVector(data.cbegin(), data.cend());
}

int string_to_byte_array(std::string str, int nBytes, unsigned char* dest)
{
   if(str.length() < nBytes * 2)
      return -1;

   for(int i = 0, j = 0 ; j < nBytes; i = i + 2, j++)
   {
      std::string byteString = str.substr(i, 2);
      unsigned char byte = (unsigned char)strtol(byteString.c_str(), NULL, 16);
      dest[j] = byte;
   }
   return 0;
}

std::string byte_array_to_string(const unsigned char* source, int nBytes)
{
   std::vector<char> result(nBytes * 2 + 1);

   for(int i = 0, j = 0 ; j < nBytes; i = i + 2, j++)
   {
      sprintf(result.data() + i, "%02x", source[j]);
   }

   return std::string(result.data(), nBytes * 2);
}

int print_bytes(const unsigned char* bytes, int length)
{
   for(int i = 0; i < length; i++)
   {
      std::cout << std::hex << std::setfill('0') << std::setw(2) << (0xFF & (int)bytes[i]);
   }
   std::cout << std::endl;
   return 0;
}

//get files recoursively
void getFileListNoPfs(boost::filesystem::path path, std::set<std::string>& files, std::set<std::string>& directories)
{
   if (!path.empty())
   {
      boost::filesystem::path apk_path(path);
      boost::filesystem::recursive_directory_iterator end;

      for (boost::filesystem::recursive_directory_iterator i(apk_path); i != end; ++i)
      {
         const boost::filesystem::path cp = (*i);

         //skip paths that are not included in files.db
         if(boost::starts_with(cp, (path / boost::filesystem::path("sce_pfs"))))
            continue;

         if(boost::starts_with(cp, (path / boost::filesystem::path("sce_sys") / boost::filesystem::path("package"))))
            continue;

         //add file or directory
         if(boost::filesystem::is_directory(cp))
            directories.insert(cp.generic_string());
         else
            files.insert(cp.generic_string());
      }
   }
}