#include "SecretGenerator.h"

#include <stdint.h>
#include <string>

#include "sha1.h"

#include "PfsKeys.h"
#include "SceKernelUtilsForDriver.h"
#include "PfsCryptEngineBase.h"

int gen_secret(unsigned char* combo_aligned, uint32_t files_salt, uint32_t unicv_page_salt)
{
   int saltin0[1] = {0};
   int saltin1[2] = {0};
   unsigned char base[0x14] = {0};

   if(files_salt == 0)
   {
      saltin0[0] = unicv_page_salt;
      SceKernelUtilsForDriver_sceHmacSha1DigestForDriver(hmac_key1, 0x14, (unsigned char*)saltin0, 4, base); // derive base with one salt
   }
   else
   {
      saltin1[0] = files_salt;
      saltin1[1] = unicv_page_salt;
      SceKernelUtilsForDriver_sceHmacSha1DigestForDriver(hmac_key1, 0x14, (unsigned char*)saltin1, 8, base); // derive base with two salts
   }

   memcpy(combo_aligned, base, 0x14); // calculated digest will be src data

   return 0;
}

int generate_secret_np(unsigned char* secret, const unsigned char* klicensee, uint32_t files_salt, uint32_t unicv_page_salt, uint16_t key_id)
{
   unsigned char drvkey[0x14] = {0};
   unsigned char iv[0x10] = {0};
   unsigned char combo[0x14] = {0};

   gen_secret(combo, files_salt, unicv_page_salt);

   memcpy(iv, iv0, 0x10); //initialize iv

   AESCBCEncryptWithKeygen_base(klicensee, iv, 0x14, combo, drvkey, key_id);

   memcpy(secret, drvkey, 0x14); // copy derived key
   
   return 0;
}

int generate_secret(unsigned char* secret, const unsigned char* klicensee,  uint32_t unicv_page_salt)
{
   int saltin[2] = {0};
   unsigned char base0[0x14] = {0};
   unsigned char base1[0x14] = {0};
   unsigned char combo[0x28] = {0};
   unsigned char drvkey[0x14] = {0};

   SceKernelUtilsForDriver_sceSha1DigestForDriver(klicensee, 0x10, base0); // calculate digest of klicensee
   
   saltin[0] = 0xA;
   saltin[1] = unicv_page_salt;

   SceKernelUtilsForDriver_sceSha1DigestForDriver((unsigned char*)saltin, 8, base1); // calculate digest of salt

   memcpy(combo, base0, 0x14);
   memcpy(combo + 0x14, base1, 0x14);
         
   SceKernelUtilsForDriver_sceSha1DigestForDriver(combo, 0x28, drvkey); // calculate digest of combination of klicensee and salt digests
               
   memcpy(secret, drvkey, 0x14); // copy derived key

   return 0;
}

int scePfsUtilGetSecret(unsigned char* secret, const unsigned char* klicensee, uint32_t files_salt, uint16_t flag, uint32_t unicv_page_salt, uint16_t key_id)
{
   if((flag & 1) > 0) // check bit 0
   {
      memset(secret, 0, 0x14);
      return 0;
   }

   if((flag & 2) > 0) // check bit 1
   {
      generate_secret_np(secret, klicensee, files_salt, unicv_page_salt, key_id);
      return 0;
   }

   return generate_secret(secret, klicensee, unicv_page_salt);
}