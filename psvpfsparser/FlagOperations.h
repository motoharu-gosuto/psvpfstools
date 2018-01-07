#pragma once

#include <cstdint>

bool scePfsIsRoImage(std::uint16_t image_spec);

bool scePfsIsRwImage(std::uint16_t image_spec);

std::uint16_t scePfsGetImageSpec(std::uint16_t mode_index);

int scePfsCheckImage(std::uint16_t mode_index, std::uint16_t expected_image_spec);