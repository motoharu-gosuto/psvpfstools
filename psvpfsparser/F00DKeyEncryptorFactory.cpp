#include "F00DKeyEncryptorFactory.h"

#include "F00DUrlKeyEncryptor.h"
#include "F00DFileKeyEncryptor.h"

std::shared_ptr<IF00DKeyEncryptor> F00DKeyEncryptorFactory::create(F00DEncryptorTypes type, std::string arg)
{
   switch(type)
   {
   case F00DEncryptorTypes::url:
      return std::make_shared<F00DUrlKeyEncryptor>(arg);
   case F00DEncryptorTypes::file:
      return std::make_shared<F00DFileKeyEncryptor>(arg);
   default:
      throw std::runtime_error("unexpected F00DEncryptorTypes value");
   }
}