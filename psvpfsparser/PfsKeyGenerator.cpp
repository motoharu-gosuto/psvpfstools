#include "PfsKeyGenerator.h"

#include <string>
#include <cstring>
#include <stdexcept>

#include "PfsKeys.h"
#include "IcvPrimitives.h"
#include "PfsCryptEngine.h"
#include "SecretGenerator.h"

//[TESTED]
int generate_enckeys(unsigned char* dec_key, unsigned char* tweak_enc_key, const unsigned char* klicensee, std::uint32_t unicv_page_salt)
{
   int saltin[2] = {0};
   unsigned char base0[0x14] = {0};
   unsigned char base1[0x14] = {0};
   
   unsigned char drvkey[0x14] = {0};

   icv_set_sw(base0, klicensee, 0x10); //calculate hash of klicensee

   saltin[0] = unicv_page_salt;

   // derive key 0

   saltin[1] = 1;
   
   icv_set_sw(base1, (unsigned char *)saltin, 8); //calculate hash of salt 0

   icv_contract(drvkey, base0, base1); //calculate hash from combination of salt 0 hash and klicensee hash

   memcpy(dec_key, drvkey, 0x10);  //copy derived key

   // derive key 1
   
   saltin[1] = 2;

   icv_set_sw(base1, (unsigned char*)saltin, 8); //calculate hash of salt 1

   icv_contract(drvkey, base0, base1); //calculate hash from combination of salt 1 hash and klicensee hash

   memcpy(tweak_enc_key, drvkey, 0x10); //copy derived key

   return 0;
}

//[TESTED]
int gen_iv(unsigned char* tweak_enc_key, std::uint32_t files_salt, std::uint32_t unicv_page_salt)
{
   unsigned char drvkey[0x14] = {0};

   if(files_salt == 0)
   {
      int saltin0[1] = {0};
      saltin0[0] = unicv_page_salt;

      icv_set_hmac_sw(drvkey, hmac_key0, (unsigned char*)saltin0, 4); // derive key with one salt
   }
   else
   {
      int saltin1[2] = {0};
      saltin1[0] = files_salt;
      saltin1[1] = unicv_page_salt;
      
      icv_set_hmac_sw(drvkey, hmac_key0, (unsigned char*)saltin1, 8); // derive key with two salts
   }

   memcpy(tweak_enc_key, drvkey, 0x10); //copy derived key

   return 0;
}

//---------------------

//[TESTED]
int scePfsUtilGetSDKeys(unsigned char* dec_key, unsigned char* tweak_enc_key, const unsigned char* klicensee, std::uint32_t files_salt, std::uint32_t unicv_page_salt)
{
  //files_salt is ignored
  return generate_enckeys(dec_key, tweak_enc_key, klicensee, unicv_page_salt);
}

//[TESTED]
int scePfsUtilGetGDKeys(unsigned char* dec_key, unsigned char* tweak_enc_key, const unsigned char* klicensee, std::uint32_t files_salt, std::uint16_t flag, std::uint32_t unicv_page_salt)
{
   if((flag & 2) > 0)
   {
      memcpy(dec_key, klicensee, 0x10);

      return gen_iv(tweak_enc_key, files_salt, unicv_page_salt);
   }
   else
   {
      return generate_enckeys(dec_key, tweak_enc_key, klicensee, unicv_page_salt);
   }
}

//[TESTED]
int scePfsUtilGetGDKeys2(unsigned char* dec_key, unsigned char* tweak_enc_key, const unsigned char* klicensee, std::uint16_t ignored_flag, std::uint16_t ignored_key_id, const unsigned char* base_key, std::uint32_t base_key_len)
{
   unsigned char drvkey[0x14] = {0};

   icv_set_hmac_sw(drvkey, hmac_key0, base_key, base_key_len);

   memcpy(dec_key, klicensee, 0x10);

   memcpy(tweak_enc_key, drvkey, 0x10);

   return 0;
}

int setup_crypt_packet_keys(CryptEngineData* data, const derive_keys_ctx* drv_ctx)
{
   int some_flag_base = (std::uint32_t)(data->pmi_bcl_flag - 2);
   int some_flag = 0xC0000B03 & (1 << some_flag_base);

   if((some_flag_base > 0x1F) || (some_flag == 0))
   {
      scePfsUtilGetSDKeys(data->dec_key, data->tweak_enc_key, data->klicensee, data->files_salt, data->unicv_page);
   }
   else
   {
      if((drv_ctx->unk_40 != 0 && drv_ctx->unk_40 != 3) || (drv_ctx->sceiftbl_version <= 1))
      {  
         scePfsUtilGetGDKeys(data->dec_key, data->tweak_enc_key, data->klicensee, data->files_salt, data->pmi_bcl_flag, data->unicv_page);
      }
      else
      {
         if(drv_ctx->unk_40 == 0 || drv_ctx->unk_40 == 3)
         {
            scePfsUtilGetGDKeys2(data->dec_key, data->tweak_enc_key, data->klicensee, data->pmi_bcl_flag, data->key_id, drv_ctx->base_key, 0x14);
         }
         else
         {
            throw std::runtime_error("Invalid set of flags in DerivePfsKeys");
         }
      }
   }

   return scePfsUtilGetSecret(data->secret, data->klicensee, data->files_salt, data->pmi_bcl_flag, data->unicv_page, data->key_id);
}