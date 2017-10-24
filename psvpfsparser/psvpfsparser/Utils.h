#pragma once

#include <stdint.h>
#include <vector>

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