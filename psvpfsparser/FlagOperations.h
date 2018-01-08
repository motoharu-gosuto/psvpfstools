#pragma once

#include <cstdint>

bool scePfsIsRoImage(std::uint16_t image_spec);

bool scePfsIsRwImage(std::uint16_t image_spec);

std::uint16_t scePfsGetImageSpec(std::uint16_t mode_index);

int scePfsCheckImage(std::uint16_t mode_index, std::uint16_t expected_image_spec);

//----------------------

struct pfs_mode_settings
{
   std::uint32_t unk_0;
   std::uint32_t db_type;
   std::uint32_t unk_8;
   std::uint32_t unk_C;

   std::uint32_t unk_10;
   std::uint32_t unk_14;
   std::uint32_t unk_18;
   std::uint32_t unk_1C;

   std::uint32_t unk_20;
   std::uint32_t unk_24;
   std::uint32_t unk_28;
   std::uint32_t unk_2C;

   std::uint32_t unk_30;
   std::uint32_t unk_34;
   std::uint32_t unk_38;
   std::uint32_t unk_3C;
};

pfs_mode_settings* scePfsGetModeSetting(std::uint16_t mode_index);

//----------------------

enum pfs_image_types : std::uint16_t
{
   gamedata = 0,
   savedata = 1,
   ac_root = 2,
   acid_dir = 3
};

int img_type_to_mode_flag(pfs_image_types img_type, std::uint16_t* mode_index, std::uint16_t* pmi_bcl_flag);

//----------------------

struct mode_to_attr_entry_t
{
  std::uint32_t mode;
  std::uint16_t attr;
  std::uint16_t unk6;
};

#define MODE_RW  0x180
#define MODE_RO  0x100
#define MORE_WO  0x080 //not sure
#define MODE_SYS 0x000

#define MODE_MASK1 (MODE_RW | MODE_RO | MORE_WO | MODE_SYS)

#define MODE_UNK0    0x1000
#define MODE_DIR     0x8000
#define MODE_ACIDDIR (MODE_UNK0 | MODE_DIR) // 0x9000

#define MODE_MASK2 (MODE_UNK0 | MODE_DIR)

#define MODE_NENC    0x100000
#define MODE_NICV    0x200000
#define MODE_NPFS    (MODE_NENC | MODE_NICV) // 0x300000

#define MODE_MASK3 (MODE_NENC | MODE_NICV)

//

//N most likely means NOT

#define ATTR_RW   0x0000
#define ATTR_WO   0x0000 //not sure
#define ATTR_RO   0x0001

#define ATTR_UNK1 0x0002
#define ATTR_UNK2 0x0004
#define ATTR_SYS  (ATTR_UNK1 | ATTR_UNK2) //0x0006

#define ATTR_UNK3 0x0400

#define ATTR_UNK0 0x1000

#define ATTR_NICV 0x2000
#define ATTR_NENC 0x4000
#define ATTR_NPFS (ATTR_NENC | ATTR_NICV) // 0x6000

#define ATTR_DIR  0x8000

//

int scePfsACSetFSAttrByMode(std::uint32_t mode, std::uint16_t* fs_attr);

int is_dir(char* string_id);

int get_file_mode(std::uint32_t* mode, char* type_string, char* string_id);

//----------------------

enum db_types : std::uint32_t
{
   SCEIFTBL_RO = 0,      // isec_restart_ro
   SCEICVDB_RW = 1,      // isec_restart_rw
   SCEINULL_NULL_RW = 2, // isec_restart_null
   SCEIFTBL_NULL_RO = 3, // isec_restart_nullro
};

db_types db_type_value_to_db_type(std::uint32_t value);
