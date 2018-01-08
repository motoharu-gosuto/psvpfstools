#include "PfsKeyGenerator.h"

#include <string>
#include <cstring>
#include <stdexcept>

#include "PfsKeys.h"
#include "IcvPrimitives.h"
#include "PfsCryptEngine.h"
#include "SecretGenerator.h"
#include "FlagOperations.h"

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

//WARNING: 0xD index appeared on 3.60

bool is_gamedata(std::uint16_t flag)
{
   int index = flag & 0xFFFF;
   
   if(index > 0x21)
      return false;
   
   switch(index)
   {
      case 0x02:
      case 0x03:
      case 0x0A:
      case 0x0B:
      case 0x0D:
      case 0x20:
      case 0x21:
         return true;

      default:
         return false;
   }
}

const unsigned char* isec_dbseed(const derive_keys_ctx* drv_ctx)
{
   //unk_40 must be equal to 0 or 3 (SCEIFTBL_RO or SCEIFTBL_NULL_RO) 
   //AND version should be > 1 showing that ricv seed is supported

   if((drv_ctx->unk_40 != 0 && drv_ctx->unk_40 != 3) || drv_ctx->icv_version <= 1)
      return 0;
   else
      return drv_ctx->dbseed;
}

//---------------------

//flag map - derivation up to this point

std::uint16_t mode_to_attr(std::uint32_t mode, bool is_dir, std::uint16_t mode_index, std::uint32_t node_index)
{
   if(is_dir)
   {
       if (mode & MODE_UNK0)
       {
          if(mode_index != 4 || node_index > 0)
          {
             std::runtime_error("invalid flags");
          }
       }
   }

   std::uint16_t flag0;

   scePfsACSetFSAttrByMode(mode, &flag0);

   if(is_dir)
   {
      flag0 |= ATTR_DIR;

      if(mode & MODE_UNK0)
         flag0 |= ATTR_UNK0;
   }

   return flag0;
}

struct filesdb_t
{
   std::uint16_t pmi_bcl_flag;
   std::uint16_t mode_index;
};

struct pfsfile_t
{
   std::uint16_t flag0;
};

db_types flags_to_unk_40(pfsfile_t* pfsf, filesdb_t* fl, bool restart)
{
   pfs_mode_settings* settings = scePfsGetModeSetting(fl->mode_index);

   db_types unk40;

   if(settings->db_type == 0)
   {
      unk40 = db_types::SCEIFTBL_RO;
   }
   else if(settings->db_type == 1)
   {
      unk40 = db_types::SCEICVDB_RW;
   }
   else
   {
      std::runtime_error("invalid index");
   }

   //if format is icv.db and (not icv or dir)
   if(settings->db_type == 1 && (pfsf->flag0 & ATTR_NICV || pfsf->flag0 & ATTR_DIR))
      unk40 = db_types::SCEINULL_NULL_RW;

   if(restart)
   {
      //if format is unicv.db and 
      if(settings->db_type == 0 && pfsf->flag0 & ATTR_UNK3)
         unk40 = db_types::SCEIFTBL_NULL_RO;
   }

  return unk40;
}

//pfsfile_open
//if ( pfsf->flag0 & 0x4000 || pfsf->flag0 & 0x8000 )
//  fa.pmi_bcl_flag |= 1u;

//isec_t is the same type as derive_keys_ctx

//this sets dctx->unk_40 field that can be used in isec_dbseed
void set_drv_ctx(derive_keys_ctx* dctx, pfs_image_types img_type, char* klicensee, char* type_string, char* string_id, std::uint32_t icv_version, bool restart)
{
   std::uint16_t mode_index;
   std::uint16_t pmi_bcl_flag;

   //convert image type to mode_index and pmi_bcl_flag

   img_type_to_mode_flag(img_type, &mode_index, &pmi_bcl_flag); 

   //adjust flags to klicensee - whats the point? it always has 1 anyway

   if (klicensee == 0)
      pmi_bcl_flag |= 1;

   //copy mode_index and pmi_bcl_flag

   filesdb_t fl;
   fl.mode_index = mode_index;
   fl.pmi_bcl_flag = pmi_bcl_flag;

   //get mode of a file

   std::uint32_t mode;
   get_file_mode(&mode, type_string, string_id);

   //convert mode to flag0

   pfsfile_t pfsf;

   pfsf.flag0 = mode_to_attr(mode, is_dir(string_id), mode_index, 0);

   //use flag0 and mode_index to convert to unk40

   dctx->unk_40 = (std::uint32_t)flags_to_unk_40(&pfsf, &fl, restart);
   dctx->icv_version = icv_version;

   //then can use all the flags

   is_gamedata(fl.pmi_bcl_flag);

   isec_dbseed(dctx);
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