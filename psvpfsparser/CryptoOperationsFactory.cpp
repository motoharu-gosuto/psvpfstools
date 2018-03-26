#include <stdexcept>

#include "CryptoOperationsFactory.h"
#include "LibTomCryptCryptoOperations.h"

std::shared_ptr<ICryptoOperations> CryptoOperationsFactory::create(CryptoOperationsTypes type)
{
   switch(type)
   {
   case CryptoOperationsTypes::libtomcrypt:
      return std::make_shared<LibTomCryptCryptoOperations>();
   default:
      throw std::runtime_error("unexpected CryptoOperationsTypes value");
   }
}