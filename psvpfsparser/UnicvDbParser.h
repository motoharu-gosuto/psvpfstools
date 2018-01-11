#pragma once

#include "UnicvDbTypes.h"

int get_isUnicv(boost::filesystem::path titleIdPath, bool& isUnicv);

int parseUnicvDb(boost::filesystem::path titleIdPath, std::shared_ptr<sce_idb_base_t>& fdb);