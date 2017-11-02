#include "PfsKeyGenerator.h"

#include <string>

#include "SceKernelUtilsForDriver.h"
#include "PfsKeys.h"
#include "CryptoEngine.h"
#include "SecretGenerator.h"

//----------------------

int sha1Digest_219DE54(unsigned char *result, const unsigned char *source, int size)
{
   return SceKernelUtilsForDriver_sceSha1DigestForDriver(source, size, result);
}

static int hmacSha1Digest_219DE68(unsigned char* digest, const unsigned char* key, const unsigned char* data, int data_len)
{
   return SceKernelUtilsForDriver_sceHmacSha1DigestForDriver(key, 0x14, data, data_len, digest);
}

//----------------------

int calculate_sha1_chain_219E008(unsigned char* key, unsigned char* iv_xor_key, const unsigned char* klicensee, uint32_t salt1)
{
   int saltin[2] = {0};
   unsigned char base0[0x14] = {0};
   unsigned char base1[0x14] = {0};
   unsigned char combo[0x28] = {0};
   unsigned char drvkey[0x14] = {0};

   saltin[0] = salt1;

   sha1Digest_219DE54(base0, klicensee, 0x10); //calculate hash of klicensee

   // derive key 0

   saltin[1] = 1;
   
   sha1Digest_219DE54(base1, (unsigned char*)saltin, 8); //calculate hash of salt 0

   memcpy(combo, base0, 0x14);
   memcpy(combo + 0x14, base1, 0x14);
   
   sha1Digest_219DE54(drvkey, combo, 0x28); //calculate hash from combination of salt 0 hash and klicensee hash

   memcpy(key, drvkey, 0x10);  //copy derived key

   // derive key 1
   
   saltin[1] = 2;

   sha1Digest_219DE54(base1, (unsigned char*)saltin, 8); //calculate hash of salt 1

   memcpy(combo, base0, 0x14);
   memcpy(combo + 0x14, base1, 0x14);

   sha1Digest_219DE54(drvkey, combo, 0x28); //calculate hash from combination of salt 1 hash and klicensee hash

   memcpy(iv_xor_key, drvkey, 0x10); //copy derived key

   return 0;
}

int calculate_sha1_chain_219E1CC(unsigned char* key, unsigned char* iv_xor_key, const unsigned char* klicensee, uint32_t ignored_salt0, uint32_t salt1)
{
   return calculate_sha1_chain_219E008(key, iv_xor_key, klicensee, salt1);
}

int hmac1_sha1_or_sha1_chain_219E0DC(unsigned char* key, unsigned char* iv_xor_key, const unsigned char* klicensee, uint32_t salt0, uint16_t flag, uint32_t salt1, uint16_t ignored_key_id)
{
   if((flag & 2) == 0)
   {
      calculate_sha1_chain_219E008(key, iv_xor_key, klicensee, salt1);
      return 0;
   }

   int saltin0[1] = {0};
   int saltin1[2] = {0};
   unsigned char drvkey[0x14] = {0};

   memcpy(key, klicensee, 0x10);

   if(salt0 == 0)
   {
      saltin0[0x00] = salt1;
      hmacSha1Digest_219DE68(drvkey, hmac_key0, (unsigned char*)saltin0, 4); // derive key with one salt
   }
   else
   {
      saltin1[0] = salt0;
      saltin1[1] = salt1;
      hmacSha1Digest_219DE68(drvkey, hmac_key0, (unsigned char*)saltin1, 8); // derive key with two salts
   }

   memcpy(iv_xor_key, drvkey, 0x10); //copy derived key

   return 0;
}

int hmac_sha1_219E164(unsigned char* key, unsigned char* iv_xor_key, const unsigned char* klicensee, uint16_t ignored_flag, uint16_t ignored_key_id, const unsigned char* base_key, uint32_t base_key_len)
{
   unsigned char drvkey[0x14] = {0};

   hmacSha1Digest_219DE68(drvkey, hmac_key0, base_key, base_key_len);

   memcpy(key, klicensee, 0x10);

   memcpy(iv_xor_key, drvkey, 0x10);

   return 0;
}

int derive_data_ctx_keys(CryptEngineData* data, const derive_keys_ctx* drv_ctx)
{
   int some_flag_base = (uint32_t)(data->pmi_bcl_flag - 2);
   int some_flag = 0xC0000B03 & (1 << some_flag_base);

   if((some_flag_base > 0x1F) || (some_flag == 0))
   {
      calculate_sha1_chain_219E1CC(data->dec_key, data->iv_key, data->klicensee, data->files_salt, data->unicv_page);
      return scePfsUtilGetSecret(data->secret, data->klicensee, data->files_salt, data->pmi_bcl_flag, data->unicv_page, data->key_id);
   }
   else
   {
      if((drv_ctx->unk_40 != 0 && drv_ctx->unk_40 != 3) || (drv_ctx->sceiftbl_version <= 1))
      {    
         hmac1_sha1_or_sha1_chain_219E0DC(data->dec_key, data->iv_key, data->klicensee, data->files_salt, data->pmi_bcl_flag, data->unicv_page, data->key_id);
         return scePfsUtilGetSecret(data->secret, data->klicensee, data->files_salt, data->pmi_bcl_flag, data->unicv_page, data->key_id);
      }
      else
      {
         if(drv_ctx->unk_40 == 0 || drv_ctx->unk_40 == 3)
         {
            hmac_sha1_219E164(data->dec_key, data->iv_key, data->klicensee, data->pmi_bcl_flag, data->key_id, drv_ctx->base_key, 0x14);
            return scePfsUtilGetSecret(data->secret, data->klicensee, data->files_salt, data->pmi_bcl_flag, data->unicv_page, data->key_id);
         }
         else
         {
            hmac_sha1_219E164(data->dec_key, data->iv_key, data->klicensee, data->pmi_bcl_flag, data->key_id, 0, 0x14);
            return scePfsUtilGetSecret(data->secret, data->klicensee, data->files_salt, data->pmi_bcl_flag, data->unicv_page, data->key_id);
         }
      }
   }
}