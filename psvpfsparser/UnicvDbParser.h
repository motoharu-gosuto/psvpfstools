#pragma once

#include "UnicvDbTypes.h"

int parseUnicvDb(boost::filesystem::path titleIdPath, std::shared_ptr<sce_idb_base_t>& fdb);