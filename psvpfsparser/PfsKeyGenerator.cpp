#include "PfsKeyGenerator.h"

#include <string>
#include <cstring>
#include <stdexcept>

#include "SceKernelUtilsForDriver.h"
#include "PfsKeys.h"
#include "PfsCryptEngine.h"
#include "SecretGenerator.h"

//similar to gen_secret in SecretGenerator
//[TESTED]
int gen_secrets_extern(unsigned char* dec_key, unsigned char* iv_key, const unsigned char* klicensee, uint16_t ignored_flag, uint16_t ignored_key_id, const unsigned char* base_key, uint32_t base_key_len)
{
   unsigned char drvkey[0x14] = {0};

   SceKernelUtilsForDriver_sceHmacSha1DigestForDriver(hmac_key0, 0x14, base_key, base_key_len, drvkey);

   memcpy(dec_key, klicensee, 0x10);

   memcpy(iv_key, drvkey, 0x10);

   return 0;
}

//similar to generate_secret in SecretGenerator
int generate_secrets(unsigned char* dec_key, unsigned char* iv_key, const unsigned char* klicensee, uint32_t unicv_page_salt)
{
   throw std::runtime_error("Untested generate_secrets");

   int saltin[2] = {0};
   unsigned char base0[0x14] = {0};
   unsigned char base1[0x14] = {0};
   unsigned char combo[0x28] = {0};
   unsigned char drvkey[0x14] = {0};

   saltin[0] = unicv_page_salt;

   SceKernelUtilsForDriver_sceSha1DigestForDriver(klicensee, 0x10, base0); //calculate hash of klicensee

   // derive key 0

   saltin[1] = 1;
   
   SceKernelUtilsForDriver_sceSha1DigestForDriver((unsigned char*)saltin, 8, base1); //calculate hash of salt 0

   memcpy(combo, base0, 0x14);
   memcpy(combo + 0x14, base1, 0x14);
   
   SceKernelUtilsForDriver_sceSha1DigestForDriver(combo, 0x28, drvkey); //calculate hash from combination of salt 0 hash and klicensee hash

   memcpy(dec_key, drvkey, 0x10);  //copy derived key

   // derive key 1
   
   saltin[1] = 2;

   SceKernelUtilsForDriver_sceSha1DigestForDriver((unsigned char*)saltin, 8, base1); //calculate hash of salt 1

   memcpy(combo, base0, 0x14);
   memcpy(combo + 0x14, base1, 0x14);

   SceKernelUtilsForDriver_sceSha1DigestForDriver(combo, 0x28, drvkey); //calculate hash from combination of salt 1 hash and klicensee hash

   memcpy(iv_key, drvkey, 0x10); //copy derived key

   return 0;
}

//similar to gen_secret in SecretGenerator
//[TESTED]
int gen_secrets(unsigned char* dec_key, unsigned char* iv_key, const unsigned char* klicensee, uint32_t files_salt, uint32_t unicv_page_salt)
{
   int saltin0[1] = {0};
   int saltin1[2] = {0};
   unsigned char drvkey[0x14] = {0};

   memcpy(dec_key, klicensee, 0x10);

   if(files_salt == 0)
   {
      saltin0[0x00] = unicv_page_salt;
      SceKernelUtilsForDriver_sceHmacSha1DigestForDriver(hmac_key0, 0x14, (unsigned char*)saltin0, 4, drvkey); // derive key with one salt
   }
   else
   {
      saltin1[0] = files_salt;
      saltin1[1] = unicv_page_salt;
      SceKernelUtilsForDriver_sceHmacSha1DigestForDriver(hmac_key0, 0x14, (unsigned char*)saltin1, 8, drvkey); // derive key with two salts
   }

   memcpy(iv_key, drvkey, 0x10); //copy derived key

   return 0;
}

int DerivePfsKeys(CryptEngineData* data, const derive_keys_ctx* drv_ctx)
{
   int some_flag_base = (uint32_t)(data->pmi_bcl_flag - 2);
   int some_flag = 0xC0000B03 & (1 << some_flag_base);

   if((some_flag_base > 0x1F) || (some_flag == 0))
   {
      generate_secrets(data->dec_key, data->iv_key, data->klicensee, data->unicv_page);
      return scePfsUtilGetSecret(data->secret, data->klicensee, data->files_salt, data->pmi_bcl_flag, data->unicv_page, data->key_id);
   }
   else
   {
      if((drv_ctx->unk_40 != 0 && drv_ctx->unk_40 != 3) || (drv_ctx->sceiftbl_version <= 1))
      {  
         if((data->pmi_bcl_flag & 2) > 0)
            gen_secrets(data->dec_key, data->iv_key, data->klicensee, data->files_salt, data->unicv_page);
         else
            generate_secrets(data->dec_key, data->iv_key, data->klicensee, data->unicv_page);

         return scePfsUtilGetSecret(data->secret, data->klicensee, data->files_salt, data->pmi_bcl_flag, data->unicv_page, data->key_id);
      }
      else
      {
         if(drv_ctx->unk_40 == 0 || drv_ctx->unk_40 == 3)
         {
            gen_secrets_extern(data->dec_key, data->iv_key, data->klicensee, data->pmi_bcl_flag, data->key_id, drv_ctx->base_key, 0x14);
            return scePfsUtilGetSecret(data->secret, data->klicensee, data->files_salt, data->pmi_bcl_flag, data->unicv_page, data->key_id);
         }
         else
         {
            throw std::runtime_error("Invalid set of flags in DerivePfsKeys");
         }
      }
   }
}