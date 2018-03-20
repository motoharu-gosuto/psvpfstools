#pragma once

class IF00DKeyEncryptor
{
public:
   virtual ~IF00DKeyEncryptor(){}

public:
   virtual int encrypt_key(const unsigned char* key, int key_size, unsigned char* drv_key) = 0;
};