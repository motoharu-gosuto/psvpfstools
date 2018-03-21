#include <stdexcept>

#include "CryptoOperationsFactory.h"

#include "DefaultCryptoOperations.h"

std::shared_ptr<ICryptoOperations> CryptoOperationsFactory::create(CryptoOperationsTypes type)
{
   switch(type)
   {
   case CryptoOperationsTypes::default:
      return std::make_shared<DefaultCryptoOperations>();
   case CryptoOperationsTypes::libtomcrypt:
      throw std::runtime_error("libtomcrypt crypto operations are not implemented");
   }
}