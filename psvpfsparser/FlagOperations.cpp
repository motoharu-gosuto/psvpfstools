#include "FlagOperations.h"

#include <stdexcept>

//set of methods to distinguish between ro and rw db by checking image spec

//this correlates with scePfsGetModeSetting method - function uses same argument as scePfsGetModeSetting
//only these indexes should correspond to game data : 0x02, 0x03, 0x0A, 0x0B, 0x0D, 0x20, 0x21
//also comparing switch statement with scePfsIsRoImage - these indexes map exactly to 1 or 4 which is RO data (game data)

//WARNING: 0xD index case may not correlate with 3.60 (applies to 3.55)

bool scePfsIsRoImage(std::uint16_t image_spec)
{
  return image_spec == 1 || image_spec == 4;
}

bool scePfsIsRwImage(std::uint16_t image_spec)
{
  return image_spec == 2 || image_spec == 3;
}

std::uint16_t scePfsGetImageSpec(std::uint16_t mode_index)
{
   std::uint16_t index = mode_index & 0xFFFF;

   if(index > 0x21)
      return 0xFFFF;
   
   switch(index)
   {
      case 0x00: 
      case 0x14: 
      case 0x15: 
      case 0x16: 
      case 0x17: 
         return 0 & 0xFFFF; // FAKE / REDIRECT

      case 0x02: 
      case 0x03: 
      case 0x0A: 
         return 1 & 0xFFFF; // IsRoImage - GAME

      case 0x04: 
      case 0x08: 
      case 0x0C: 
         return 3 & 0xFFFF; // AC

      case 0x05:
      case 0x06:
      case 0x07:
      case 0x09: 
         return 2 & 0xFFFF; // SAVEDATA
      
      case 0x0B:
      case 0x20:
      case 0x21: 
         return 4 & 0xFFFF; // IsRoImage - AC

      default: 
         throw std::runtime_error("Invalid index");
   }
}

int scePfsCheckImage(std::uint16_t mode_index, std::uint16_t expected_image_spec)
{
  if(scePfsGetImageSpec(mode_index) != expected_image_spec)
     return -1;
  return 0;
}