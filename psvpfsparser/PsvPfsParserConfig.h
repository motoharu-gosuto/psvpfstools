#pragma once

#include <string>

struct PsvPfsParserConfig
{
   std::string title_id_src;
   std::string title_id_dst;
   std::string klicensee;
   std::string f00d_url;
};

int parse_options(int argc, char* argv[], PsvPfsParserConfig& cfg);