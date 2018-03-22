#pragma once

#include <memory>

#include "ICryptoOperations.h"

enum class CryptoOperationsTypes
{
   libtomcrypt
};

class CryptoOperationsFactory
{
public:
   static std::shared_ptr<ICryptoOperations> create(CryptoOperationsTypes type);
};