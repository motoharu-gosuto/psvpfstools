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
      throw std::runtime_error("Invalid index");
   
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

pfs_image_types img_spec_to_img_type(std::uint16_t image_spec)
{
   std::uint16_t index = image_spec & 0xFFFF;

   if(index > 4)
      throw std::runtime_error("Invalid index");
   
   switch(index)
   {
   case 0:
      throw std::runtime_error("Invalid index");
   case 1:
      return gamedata;
   case 2:
      return savedata;
   case 3:
      return ac_root;
   case 4:
      return acid_dir;
   default: 
      throw std::runtime_error("Invalid index");
   }
}

//this function derives mode_index from image_type

std::uint16_t img_type_to_mode_index(pfs_image_types img_type)
{
   switch(img_type)
   {
   case gamedata:
      {
         return 0x0A; // gPackSetting - ro image - (image spec 1)
      }
      break;
   case savedata:
      {
         return 0x05; // gSdSetting - rw image - (image spec 2)
      }
      break;
   case ac_root:
      {
         return 0x04; // gAcSetting - rw image - (image spec 3)
      }
      break;
   case acid_dir:
      {
         return 0x0B; // gPackSetting - ro image - (image spec 4)
      }
      break;
   default:
      throw std::runtime_error("Invalid index");
   }

   return 0;
}

//----------------------

mode_to_attr_entry_t genericMode2AttrTbl[4] = 
{
   {MODE_SYS, ATTR_SYS, 0}, //sys
   {MODE_RO,  ATTR_RO,  0}, //ro
   {MORE_WO,  ATTR_WO,  0}, //wo - not sure
   {MODE_RW,  ATTR_RW,  0}, //rw
};

mode_to_attr_entry_t specificMode2AttrTbl[4] = 
{
   {0x000000,  0x0000,    0}, 
   {MODE_NENC, ATTR_NENC, 0}, //nenc
   {MODE_NICV, ATTR_NICV, 0}, //nicv
   {MODE_NPFS, ATTR_NPFS, 0}, //npfs
};

//it looks like this code encodes sce_ng_pfs_file_types

//sets fs_attr when mode is (MODE_RO, MORE_WO or MODE_RW) or mode is (MODE_NENC or MODE_NICV)
//meaning that generic part can take values 0x0000, 0x0001, 0x0006
//meaning that specific part can take values 0x100000, 0x200000

int scePfsACSetFSAttrByMode(std::uint32_t mode, std::uint16_t* fs_attr)
{
   std::uint16_t generic = 0;

   int i;
  
   for(i = 0; i < 4; ++i)
   {
      if(genericMode2AttrTbl[i].mode == (mode & MODE_MASK1))
      {
         generic = genericMode2AttrTbl[i].attr;
         break;
      }
   }

   if(i == 4)
      return -9;

   std::uint16_t specific = 0;

   int j;

   for(j = 0; j < 4; ++j)
   {
      if(specificMode2AttrTbl[j].mode == (mode & MODE_MASK3))
      {
         specific = specificMode2AttrTbl[j].attr;
         break;
      }
   }

   if(j == 4)
      return -9;

   *fs_attr = generic | specific;

   return 0;
}

int is_dir(char* string_id)
{
  return !strcmp(string_id, "dir") || !strcmp(string_id, "aciddir");
}

//maybe related to https://github.com/weaknespase/PkgDecrypt/blob/master/pkg_dec.c#L454

int get_file_mode(std::uint32_t* mode, char* type_string, char* string_id)
{
   *mode = 0;

   if(!strcmp(type_string, "") || !strcmp(type_string, "rw"))
   {
      *mode |= MODE_RW;
   }
   else if(!strcmp(type_string, "ro"))
   {
      *mode |= MODE_RO;
   }
   else if(!strcmp(type_string, "sys"))
   {
      *mode |= MODE_SYS;
   }
   else
   {
      std::runtime_error("invalid type_string");
   }
  
   if(!strcmp(string_id, ""))
   {
      return 0;
   }
   else if(!strcmp(string_id, "aciddir"))
   {
      *mode |= MODE_ACIDDIR;
      return 0;
   }
   else if(!strcmp(string_id, "dir"))
   {
      *mode |= MODE_DIR;
      return 0;
   }
   else if(!strcmp(string_id, "npfs"))
   {
      *mode |= MODE_NPFS;
      return 0;
   }
   else if(!strcmp(string_id, "nenc"))
   {
      *mode |= MODE_NENC;
      return 0;
   }
   else if(!strcmp(string_id, "nicv"))
   {
      *mode |= MODE_NICV;
      return 0;
   }
   else
   {
      std::runtime_error("invalid string_id");
   }

   return 0;
}

//----------------------

//pseudo implementation based on isec_restart and isec_start
//converts db_type value to db_type in derive_keys_ctx 

//remember that db_type is used to select dbseed
//this map function correlates with dbseed rule
//since only mode 0 and 3 allows to select seed (icv does not support seeds)

db_types db_type_value_to_db_type(std::uint32_t value)
{
   switch(value)
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

//pseudo implementation that generates flags for scePfsUtilGetSecret function
//based on image type - I was not able to figure out how real flags are calculated

std::uint16_t img_spec_to_pmi_bcl_flag(std::uint16_t image_spec)
{
   pfs_image_types img_type = img_spec_to_img_type(image_spec);

   switch(img_type)
   {
   case pfs_image_types::gamedata:
      return 2;
   case pfs_image_types::savedata:
      return 0;
   default:
      return 1;
   }
}

//pseudo function that returns image type based on the fact that data is unicv.db

pfs_image_types is_unicv_to_img_type(bool isUnicv)
{
   if(isUnicv)
      return pfs_image_types::gamedata;
   else
      return pfs_image_types::savedata;
}