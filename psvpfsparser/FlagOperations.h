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