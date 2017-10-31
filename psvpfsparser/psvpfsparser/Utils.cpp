#include <stdint.h>
#include <vector>

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