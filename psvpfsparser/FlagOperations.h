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
   std::uint32_t unk_4;
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

enum db_types : std::uint32_t
{
   SCEIFTBL_RO = 0,      // isec_restart_ro
   SCEICVDB_RW = 1,      // isec_restart_rw
   SCEINULL_NULL_RW = 2, // isec_restart_null
   SCEIFTBL_NULL_RO = 3, // isec_restart_nullro
};

db_types unk_40_to_db_type(std::uint32_t unk_40);