#include "PsvPfsParserConfig.h"

#include <string>
#include <iostream>

#include <boost/program_options.hpp>

#define HELP_NAME "help"
#define TITLE_ID_SRC_NAME "title_id_src"
#define TITLE_ID_DST_NAME "title_id_dst"
#define KLICENSEE_NAME "klicensee"
#define ZRIF_NAME "zRIF"
#define F00D_URL_NAME "f00d_url"

int parse_options(int argc, char* argv[], PsvPfsParserConfig& cfg)
{
  try
  {
    boost::program_options::options_description desc("Options");
    desc.add_options()
      ((std::string(HELP_NAME) + ",h").c_str(), "Show help")
      ((std::string(TITLE_ID_SRC_NAME) + ",i").c_str(), boost::program_options::value<std::string>(), "Source directory that contains the application. Like PCSC00000.")
      ((std::string(TITLE_ID_DST_NAME) + ",o").c_str(), boost::program_options::value<std::string>(), "Destination directory where everything will be unpacked. Like PCSC00000_dec.")
      ((std::string(KLICENSEE_NAME) + ",k").c_str(), boost::program_options::value<std::string>(), "klicensee hex coded string. Like 00112233445566778899AABBCCDDEEFF.")
      ((std::string(ZRIF_NAME) + ",z").c_str(), boost::program_options::value<std::string>(), "zRIF string.")
      ((std::string(F00D_URL_NAME) + ",f").c_str(), boost::program_options::value<std::string>(), "Url of F00D service.");

    boost::program_options::variables_map vm;
    store(parse_command_line(argc, argv, desc), vm);
    notify(vm);

    if(vm.count(HELP_NAME))
    {
      std::cout << desc << std::endl;
      return -1;
    }

    if (vm.count(TITLE_ID_SRC_NAME))
    {
       cfg.title_id_src = vm[TITLE_ID_SRC_NAME].as<std::string>();
    }
    else
    {
       std::cout << "Missing option --" << TITLE_ID_SRC_NAME << std::endl;
       return -1;
    }

    if (vm.count(TITLE_ID_DST_NAME))
    {
       cfg.title_id_dst = vm[TITLE_ID_DST_NAME].as<std::string>();
    }
    else
    {
       std::cout << "Missing option --" << TITLE_ID_DST_NAME << std::endl;
       return -1;
    }

    if (vm.count(KLICENSEE_NAME))
    {
       cfg.klicensee = vm[KLICENSEE_NAME].as<std::string>();
    }
    else
    {
       if (vm.count(ZRIF_NAME))
       {
          cfg.zRIF = vm[ZRIF_NAME].as<std::string>();
       }
       else
       {
          std::cout << "Missing option --" << KLICENSEE_NAME << " or --"  ZRIF_NAME << std::endl;
          std::cout << "sealedkey will be used" << std::endl;
       }
    }

    if (vm.count(F00D_URL_NAME))
    {
       cfg.f00d_url = vm[F00D_URL_NAME].as<std::string>();
    }
    else
    {
       std::cout << "Missing option --" << F00D_URL_NAME << std::endl;
       return -1;
    }

    return 0;
  }
  catch (const boost::program_options::error &ex)
  {
    std::cerr << ex.what() << std::endl;
    return -1;
  }
}