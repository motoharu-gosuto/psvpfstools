#pragma once

#include "UnicvDbTypes.h"

int parseUnicvDb(boost::filesystem::path titleIdPath, std::shared_ptr<scei_db_base_t>& fdb);