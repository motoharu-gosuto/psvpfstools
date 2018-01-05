#include "PfsKeyGenerator.h"

#include <string>
#include <cstring>
#include <stdexcept>

#include "PfsKeys.h"
#include "IcvPrimitives.h"
#include "PfsCryptEngine.h"
#include "SecretGenerator.h"

//[TESTED]
int generate_enckeys(unsigned char* dec_key, unsigned char* tweak_enc_key, const unsigned char* klicensee, std::uint32_t icv_salt)
{
   int saltin[2] = {0};
   unsigned char base0[0x14] = {0};
   unsigned char base1[0x14] = {0};
   
   unsigned char drvkey[0x14] = {0};

   icv_set_sw(base0, klicensee, 0x10); //calculate hash of klicensee

   saltin[0] = icv_salt;

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
int gen_iv(unsigned char* tweak_enc_key, std::uint32_t files_salt, std::uint32_t icv_salt)
{
   unsigned char drvkey[0x14] = {0};

   if(files_salt == 0)
   {
      int saltin0[1] = {0};
      saltin0[0] = icv_salt;

      icv_set_hmac_sw(drvkey, hmac_key0, (unsigned char*)saltin0, 4); // derive key with one salt
   }
   else
   {
      int saltin1[2] = {0};
      saltin1[0] = files_salt;
      saltin1[1] = icv_salt;
      
      icv_set_hmac_sw(drvkey, hmac_key0, (unsigned char*)saltin1, 8); // derive key with two salts
   }

   memcpy(tweak_enc_key, drvkey, 0x10); //copy derived key

   return 0;
}

//---------------------

//[TESTED]
int scePfsUtilGetSDKeys(unsigned char* dec_key, unsigned char* tweak_enc_key, const unsigned char* klicensee, std::uint32_t files_salt, std::uint32_t icv_salt)
{
  //files_salt is ignored
  return generate_enckeys(dec_key, tweak_enc_key, klicensee, icv_salt);
}

//[TESTED]
int scePfsUtilGetGDKeys(unsigned char* dec_key, unsigned char* tweak_enc_key, const unsigned char* klicensee, std::uint32_t files_salt, std::uint16_t flag, std::uint32_t icv_salt)
{
   if((flag & 2) > 0)
   {
      memcpy(dec_key, klicensee, 0x10);

      return gen_iv(tweak_enc_key, files_salt, icv_salt);
   }
   else
   {
      return generate_enckeys(dec_key, tweak_enc_key, klicensee, icv_salt);
   }
}

//[TESTED]
int scePfsUtilGetGDKeys2(unsigned char* dec_key, unsigned char* tweak_enc_key, const unsigned char* klicensee, std::uint16_t ignored_flag, std::uint16_t ignored_key_id, const unsigned char* dbseed, std::uint32_t dbseed_len)
{
   unsigned char drvkey[0x14] = {0};

   icv_set_hmac_sw(drvkey, hmac_key0, dbseed, dbseed_len);

   memcpy(dec_key, klicensee, 0x10);

   memcpy(tweak_enc_key, drvkey, 0x10);

   return 0;
}

//---------------------

int is_gamedata(std::uint16_t flag)
{
   unsigned int some_flag_base = (std::uint32_t)(flag - 2); // 2 because 2 is a minimal index that should give 1 as result
   unsigned int some_flag = 0xC0000B03 & (1 << some_flag_base);

   //0x1F + 2 = 0x21 - everything that is greater than 0x21 should give 0
   //negative numbers 0 - 2, 1 - 2 will give 0 as well by first condition
   bool is_savedata = (some_flag_base > 0x1F) || (some_flag == 0);

   return !is_savedata;
}

bool is_gamedata2(std::uint16_t flag)
{
   int index = flag & 0xFFFF;
   
   if(index > 0x21)
   {
      return 0;
   }
   else
   {
      switch(index)
      {
         case 0x00: //000000
         case 0x01: //000001

         case 0x0D: //001101
         case 0x0E: //001110
         case 0x0F: //001111

         case 0x10:
         case 0x11:
         case 0x12:
         case 0x13:
         case 0x14:
         case 0x15:
         case 0x16:
         case 0x17:
         case 0x18:
         case 0x19:
         case 0x1A:
         case 0x1B:
         case 0x1C:
         case 0x1D:
         case 0x1E:
         case 0x1F:
            return 0;

         case 0x04: //000100
         case 0x05: //000101
         case 0x06: //000110
         case 0x07: //000111
         case 0x08: //001000
         case 0x09: //001001

         case 0x0C: //001100
            return 0;
         
         case 0x02: //000010
         case 0x03: //000011 

         case 0x0A: //001010
         case 0x0B: //001011

         case 0x20: //100000
         case 0x21: //100001
            return 1;
      }

      return 0;
   }
}

bool condition0(const derive_keys_ctx* drv_ctx)
{
   throw std::runtime_error("Not implemented");

   /*
   return (drv_ctx->unk_40 == 0 || drv_ctx->unk_40 == 3);
   */
}

const unsigned char* isec_dbseed(const derive_keys_ctx* drv_ctx)
{
   throw std::runtime_error("Not implemented");

   /*
   //bool res = (!condition0(drv_ctx)) || (drv_ctx->sceiftbl_version <= 1);
   //return !res;

   return drv_ctx->dbseed;
   */
}

//---------------------

int setup_crypt_packet_keys(CryptEngineData* data, const derive_keys_ctx* drv_ctx)
{
   if(is_gamedata(data->pmi_bcl_flag))
   {
      if(isec_dbseed(drv_ctx))
      {  
         scePfsUtilGetGDKeys2(data->dec_key, data->tweak_enc_key, data->klicensee, data->pmi_bcl_flag, data->key_id, isec_dbseed(drv_ctx), 0x14);  
      }
      else
      {
         scePfsUtilGetGDKeys(data->dec_key, data->tweak_enc_key, data->klicensee, data->files_salt, data->pmi_bcl_flag, data->icv_salt);
      }
   }
   else
   {
      scePfsUtilGetSDKeys(data->dec_key, data->tweak_enc_key, data->klicensee, data->files_salt, data->icv_salt);
   }

   return scePfsUtilGetSecret(data->secret, data->klicensee, data->files_salt, data->pmi_bcl_flag, data->icv_salt, data->key_id);
}