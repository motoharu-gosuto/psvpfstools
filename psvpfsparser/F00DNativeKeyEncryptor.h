#pragma once

#include <map>

#include <boost/filesystem.hpp>

#include "IF00DKeyEncryptor.h"
#include "ICryptoOperations.h"

class F00DNativeKeyEncryptor : public IF00DKeyEncryptor
{
private:
   std::map<std::string, std::string> m_keyCache;

   std::shared_ptr<ICryptoOperations> m_cryptops;

public:
   F00DNativeKeyEncryptor(std::shared_ptr<ICryptoOperations> cryptops);

private:
   int kprx_auth_service_0x50001(const unsigned char* key, int key_size, unsigned char* drv_key, int key_id) const;

public:
   int encrypt_key(const unsigned char* key, int key_size, unsigned char* drv_key) override;

   void print_cache(std::ostream& os, std::string sep = "\t") const override;
};