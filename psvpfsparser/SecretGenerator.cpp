#include "SecretGenerator.h"

#include <cstdint>
#include <string>
#include <stdexcept>

#include <libcrypto/sha1.h>

#include "PfsKeys.h"
#include "IcvPrimitives.h"

#include "PfsCryptEngineBase.h"
#include "FilesDbParser.h"

//[TESTED both branches]
int gen_secret(unsigned char* combo_aligned, std::uint32_t files_salt, std::uint32_t unicv_page_salt)
{
   unsigned char base[0x14] = {0};

   if(files_salt == 0)
   {
      int saltin0[1] = {0};
      saltin0[0] = unicv_page_salt;
      icv_set_hmac_sw(base, hmac_key1, (unsigned char*)saltin0, 4); // derive base with one salt
   }
   else
   {
      int saltin1[2] = {0};
      saltin1[0] = files_salt;
      saltin1[1] = unicv_page_salt;
      icv_set_hmac_sw(base, hmac_key1, (unsigned char*)saltin1, 8); // derive base with two salts
   }

   memcpy(combo_aligned, base, 0x14); // calculated digest will be src data

   return 0;
}

//[TESTED]
int generate_secret_np(unsigned char* secret, const unsigned char* klicensee, std::uint32_t files_salt, std::uint32_t unicv_page_salt, std::uint16_t key_id)
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

//[TESTED]
int generate_secret(unsigned char* secret, const unsigned char* klicensee,  std::uint32_t unicv_page_salt)
{
   int saltin[2] = {0};
   unsigned char base0[0x14] = {0};
   unsigned char base1[0x14] = {0};
   unsigned char drvkey[0x14] = {0};

   icv_set_sw(base0, klicensee, 0x10); // calculate digest of klicensee

   saltin[0] = 0xA;
   saltin[1] = unicv_page_salt;

   icv_set_sw(base1, (unsigned char*)saltin, 8); // calculate digest of salt

   icv_contract(drvkey, base0, base1); // calculate digest of combination of klicensee and salt digests
               
   memcpy(secret, drvkey, 0x14); // copy derived key

   return 0;
}

int scePfsUtilGetSecret(unsigned char* secret, const unsigned char* klicensee, std::uint32_t files_salt, std::uint16_t flag, std::uint32_t unicv_page_salt, std::uint16_t key_id)
{
   if((flag & 1) > 0) // check bit 0
   {
      throw std::runtime_error("Untested branch in scePfsUtilGetSecret");

      memset(secret, 0, 0x14);
      return 0;
   }
   if((flag & 2) > 0) // check bit 1
   {
      return generate_secret_np(secret, klicensee, files_salt, unicv_page_salt, key_id);
   }
   else
   {
      return generate_secret(secret, klicensee, unicv_page_salt);
   }
}

//convert pfs type flag to the flags for key derivation
int secret_type_to_flag(sce_ng_pfs_header_t& header)
{
   if(header.type == FILES_GAME_TYPE)
   {
      return 2;  
   }
   else if(header.type == FILES_TROPHY_SAVE_TYPE)
   {
      return 0;
   }
   else
   {
      return 1;
   }
}