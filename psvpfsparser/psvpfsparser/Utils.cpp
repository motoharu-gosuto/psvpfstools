#include <stdint.h>
#include <vector>

#include "Utils.h"

bool isZeroVector(std::vector<uint8_t>& data)
{
   return isZeroVector(data.cbegin(), data.cend());
}