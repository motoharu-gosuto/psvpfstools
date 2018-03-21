#pragma once

#include <string>
#include <memory>

#include "IF00DKeyEncryptor.h"

enum class F00DEncryptorTypes
{
   url,
   file
};

class F00DKeyEncryptorFactory
{
public:
   static std::shared_ptr<IF00DKeyEncryptor> create(F00DEncryptorTypes type, std::string arg);
};