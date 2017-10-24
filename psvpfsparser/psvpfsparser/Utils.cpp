#include <stdint.h>
#include <vector>

#include "Utils.h"

bool isZeroVector(std::vector<uint8_t> data)
{
   for(std::vector<uint8_t>::const_iterator it = data.begin(); it != data.end(); ++it)
   {
      if((*it) != 0)
         return false;
   }
   return true;
}