#pragma once

#include <string>

#include "F00DKeyEncryptorFactory.h"

struct PsvPfsParserConfig
{
   std::string title_id_src;
   std::string title_id_dst;
   std::string klicensee;
   std::string zRIF;
   F00DEncryptorTypes f00d_enc_type;
   std::string f00d_arg;
};

int parse_options(int argc, char* argv[], PsvPfsParserConfig& cfg);