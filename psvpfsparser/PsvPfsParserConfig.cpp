#include "PsvPfsParserConfig.h"

#include <boost/program_options.hpp>

#define HELP_NAME "help"
#define TITLE_ID_SRC_NAME "title_id_src"
#define TITLE_ID_DST_NAME "title_id_dst"
#define KLICENSEE_NAME "klicensee"
#define F00D_URL_NAME "f00d_url"

int parse_options(int argc, char* argv[], PsvPfsParserConfig& cfg)
{
  try
  {
    boost::program_options::options_description desc("Options");
    desc.add_options()
      (HELP_NAME, "Show help")
      (TITLE_ID_SRC_NAME, boost::program_options::value<std::string>()->required(), "Source directory that contains the application. Like PCSC00000")
      (TITLE_ID_DST_NAME, boost::program_options::value<std::string>()->required(), "Destination directory where everything will be unpacked. Like PCSC00000_dec")
      (KLICENSEE_NAME, boost::program_options::value<std::string>()->required(), "klicensee hex coded string. Like 00112233445566778899AABBCCDDEEFF")
      (F00D_URL_NAME, boost::program_options::value<std::string>()->required(), "Url of F00D service");

    boost::program_options::variables_map vm;
    store(parse_command_line(argc, argv, desc), vm);
    notify(vm);

    if(vm.count(HELP_NAME))
    {
      std::cout << desc << std::endl;
      return -1;
    }

    if (vm.count(TITLE_ID_SRC_NAME))
       cfg.title_id_src = vm[TITLE_ID_SRC_NAME].as<std::string>();
    if (vm.count(TITLE_ID_DST_NAME))
       cfg.title_id_dst = vm[TITLE_ID_DST_NAME].as<std::string>();
    if (vm.count(KLICENSEE_NAME))
       cfg.klicensee = vm[KLICENSEE_NAME].as<std::string>();
    if (vm.count(F00D_URL_NAME))
       cfg.f00d_url = vm[F00D_URL_NAME].as<std::string>();

    return 0;
  }
  catch (const boost::program_options::error &ex)
  {
    std::cerr << ex.what() << std::endl;
    return -1;
  }
}