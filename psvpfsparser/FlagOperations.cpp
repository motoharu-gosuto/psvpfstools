#include "FlagOperations.h"

#include <stdexcept>

//set of methods to distinguish between ro and rw db by checking image spec

//this correlates with scePfsGetModeSetting method - function uses same argument as scePfsGetModeSetting
//only these indexes should correspond to game data : 0x02, 0x03, 0x0A, 0x0B, 0x0D, 0x20, 0x21
//also comparing switch statement with scePfsIsRoImage - these indexes map exactly to 1 or 4 which is RO data (game data)

//WARNING: 0xD index case may not correlate with 3.60 (not present on 3.55)

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

//----------------------

//00 - fake
pfs_mode_settings gFakeSetting =       { 0x00000002, 0x00000002, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
                                         0x90909090, 0x90909090, 0x90909090, 0x90909090, 0x90909090, 0x90909090};

//02 - GD (Game Data)
pfs_mode_settings gGdgpSetting =       { 0x00000001, 0x00000000, 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000001, 0x00000001, 0x00000001, 
                                         0x90909090, 0x90909090, 0x90909090, 0x90909090, 0x90909090, 0x90909090};

//03 - GD (?)
pfs_mode_settings gGpwrSetting =       { 0x00000001, 0x00000000, 0x00000001, 0x00000000, 0x00000000, 0x00000180, 0x000001C0, 0x00000001, 0x00000000, 0x00000001, 
                                         0x90909090, 0x90909090, 0x90909090, 0x90909090, 0x90909090, 0x90909090};

//04, 08 - AC (AC Pseudo Drive)
pfs_mode_settings gAcSetting =         { 0x00000000, 0x00000001, 0x00000001, 0x00000102, 0x00000102, 0x00000180, 0x000001C0, 0x00000000, 0x00000000, 0x00000000, 
                                         0x90909090, 0x90909090, 0x90909090, 0x90909090, 0x90909090, 0x90909090};

//05, 06, 07, 09 (Save Data)
pfs_mode_settings gSdSetting =         { 0x00000000, 0x00000001, 0x00000001, 0x00000102, 0x00000102, 0x00000180, 0x000001C0, 0x00000000, 0x00000000, 0x00000000, 
                                         0x90909090, 0x90909090, 0x90909090, 0x90909090, 0x90909090, 0x90909090};

//0A, 0B (in terms of pfs - pack means unicv.db - pack of icv files)
pfs_mode_settings gPackSetting =       { 0x00000001, 0x00000000, 0x00000001, 0x00000102, 0x00000102, 0x00000180, 0x000001C0, 0x00000000, 0x00000000, 0x00000001, 
                                         0x90909090, 0x90909090, 0x90909090, 0x90909090, 0x90909090, 0x90909090};

//0C - AC (AC Pseudo Drive)
pfs_mode_settings gAcroSetting =       { 0x00000000, 0x00000001, 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000001, 0x00000001, 0x00000000, 
                                         0x90909090, 0x90909090, 0x90909090, 0x90909090, 0x90909090, 0x90909090};

//14 - REDIRECT (Redirect Pseudo Drive)
pfs_mode_settings gRedirectRoSetting = { 0x00000002, 0x00000002, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000001, 0x00000001, 0x00000000, 
                                         0x90909090, 0x90909090, 0x90909090, 0x90909090, 0x90909090, 0x90909090};

//15, 16, 17 - REDIRECT (Redirect Pseudo Drive)
pfs_mode_settings gRedirectSetting =   { 0x00000002, 0x00000002, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 
                                         0x90909090, 0x90909090, 0x90909090, 0x90909090, 0x90909090, 0x90909090};

//20, 21 - AC (AC Pseudo Drive)
pfs_mode_settings gAcContSetting =     { 0x00000001, 0x00000000, 0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000001, 0x00000001, 0x00000001, 
                                         0x90909090, 0x90909090, 0x90909090, 0x90909090, 0x90909090, 0x90909090};

//settings correlate with is_gamedata
//only 0x02, 0x03, 0x0A, 0x0B, 0x0D, 0x20, 0x21 - have unk_4 == 0 (except from 0xD which does not correlate with 3.60)
//unk_4 affects the condition that selects if data has dbseed or not
//so it probably means that 0 is gamedata
//names of settings also kinda correlate (GD, SD, AC, REDIRECT etc)

//WARNING: 0xD index case may not correlate with 3.60 (not present on 3.55)

pfs_mode_settings* scePfsGetModeSetting(std::uint16_t mode_index)
{
   std::uint16_t index = mode_index & 0xFFFF;
   
   if(index > 0x21)
      throw std::runtime_error("Invalid index");
   
   switch(index)
   {
      case 0x00: 
         return &gFakeSetting;       // unk_4 = 0x00000002

      case 0x02: 
         return &gGdgpSetting;       // unk_4 = 0x00000000 - GAME

      case 0x03: 
         return &gGpwrSetting;       // unk_4 = 0x00000000 - GAME

      case 0x04:
      case 0x08: 
         return &gAcSetting;         // unk_4 = 0x00000001

      case 0x05:
      case 0x06:
      case 0x07:
      case 0x09:
         return &gSdSetting;         // unk_4 = 0x00000001

      case 0x0A:
      case 0x0B:
         return &gPackSetting;       // unk_4 = 0x00000000 - GAME

      case 0x0C: 
         return &gAcroSetting;       // unk_4 = 0x00000001

      case 0x14: 
         return &gRedirectRoSetting; // unk_4 = 0x00000002

      case 0x15:
      case 0x16:
      case 0x17:
         return &gRedirectSetting;   // unk_4 = 0x00000002

      case 0x20: 
      case 0x21: 
         return &gAcContSetting;     // unk_4 = 0x00000000 - GAME

      default:
         throw std::runtime_error("Invalid index");
   }
}

//----------------------

//this function derives mode_index and pmi_bcl_flag from image_type

int img_type_to_mode_flag(pfs_image_types img_type, std::uint16_t* mode_index, std::uint16_t* pmi_bcl_flag)
{
   switch(img_type)
   {
   case gamedata:
      {
         *mode_index = 0x0A; // gPackSetting - ro image - (image spec 1)
         *pmi_bcl_flag = 1;
         *pmi_bcl_flag |= 2;
      }
      break;
   case savedata:
      {
         *mode_index = 0x05; // gSdSetting - rw image - (image spec 2)
         *pmi_bcl_flag = 1;
      }
      break;
   case ac_root:
      {
         *mode_index = 0x04; // gAcSetting - rw image - (image spec 3)
         *pmi_bcl_flag = 1;
      }
      break;
   case acid_dir:
      {
         *mode_index = 0x0B; // gPackSetting - ro image - (image spec 4)
         *pmi_bcl_flag = 1;
         *pmi_bcl_flag |= 2;
      }
      break;
   default:
      throw std::runtime_error("Invalid index");
   }

   return 0;
}

//pseudo implementation based on isec_restart and isec_start
//converts unk_40 from derive_keys_ctx to db_types

//remember that unk_40 is used to select dbseed
//this map function correlates with dbseed rule
//since only mode 0 and 3 allows to select seed (icv does not support seeds)

db_types unk_40_to_db_type(std::uint32_t unk_40)
{
   switch(unk_40)
   {
   case 0:
      return SCEIFTBL_RO;
   case 1:
      return SCEICVDB_RW;
   case 2:
      return SCEINULL_NULL_RW;
   case 3:
      return SCEIFTBL_NULL_RO;
   default:
      throw std::runtime_error("Invalid index");
   }
}