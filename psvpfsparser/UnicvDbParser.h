#pragma once

#include <memory>

#include "UnicvDbTypes.h"

class UnicvDbParser
{
private:
   boost::filesystem::path m_titleIdPath;

   std::shared_ptr<sce_idb_base_t> m_fdb;

public:
   UnicvDbParser(boost::filesystem::path titleIdPath);

public:
   int parse();

public:
   const std::shared_ptr<sce_idb_base_t>& get_idatabase() const;
};
