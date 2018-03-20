#include "F00DKeyEncryptorFactory.h"

#include "F00DUrlKeyEncryptor.h"

static std::string g_F00D_url;

void set_F00D_url(std::string url)
{
   g_F00D_url = url;
}

static std::shared_ptr<IF00DKeyEncryptor> g_F00D_encryptor;

//this function should be protected by mutex
//it is not relevant though since singleton will be soon removed
std::shared_ptr<IF00DKeyEncryptor> get_F00D_encryptor()
{
   if(!g_F00D_encryptor)
      g_F00D_encryptor = std::make_shared<F00DUrlKeyEncryptor>(g_F00D_url);
   return g_F00D_encryptor;
}