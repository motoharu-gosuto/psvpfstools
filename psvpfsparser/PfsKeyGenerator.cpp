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
int scePfsUtilGetGDKeys(unsigned char* dec_key, unsigned char* tweak_enc_key, const unsigned char* klicensee, std::uint32_t files_salt, std::uint16_t pmi_bcl_flag, std::uint32_t icv_salt)
{
   if((pmi_bcl_flag & 2) > 0)
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
int scePfsUtilGetGDKeys2(unsigned char* dec_key, unsigned char* tweak_enc_key, const unsigned char* klicensee, const unsigned char* dbseed, std::uint32_t dbseed_len)
{
   unsigned char drvkey[0x14] = {0};

   icv_set_hmac_sw(drvkey, hmac_key0, dbseed, dbseed_len);

   memcpy(dec_key, klicensee, 0x10);

   memcpy(tweak_enc_key, drvkey, 0x10);

   return 0;
}

//---------------------

//WARNING: 0xD index appeared on 3.60

bool is_gamedata(std::uint16_t pmi_bcl_flag)
{
   int index = pmi_bcl_flag & 0xFFFF;
   
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
   //db_type must be equal to 0 or 3 (SCEIFTBL_RO or SCEIFTBL_NULL_RO) 
   //AND version should be > 1 showing that ricv seed is supported

   if((drv_ctx->db_type != db_types::SCEIFTBL_RO && drv_ctx->db_type != db_types::SCEIFTBL_NULL_RO) || drv_ctx->icv_version <= 1)
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

   std::uint16_t fs_attr;

   scePfsACSetFSAttrByMode(mode, &fs_attr);

   if(is_dir)
   {
      fs_attr |= ATTR_DIR;

      if(mode & MODE_UNK0)
         fs_attr |= ATTR_UNK0;
   }

   return fs_attr;
}

struct filesdb_t
{
   std::uint16_t mode_index;
};

struct pfsfile_t
{
   std::uint16_t fs_attr;
};

db_types flags_to_db_type(pfsfile_t* pfsf, filesdb_t* fl, bool restart)
{
   pfs_mode_settings* settings = scePfsGetModeSetting(fl->mode_index);

   db_types type;

   if(settings->db_type == 0)
   {
      type = db_types::SCEIFTBL_RO;
   }
   else if(settings->db_type == 1)
   {
      type = db_types::SCEICVDB_RW;
   }
   else
   {
      std::runtime_error("invalid index");
   }

   //if format is icv.db and (not icv or dir)
   if(settings->db_type == 1 && (pfsf->fs_attr & ATTR_NICV || pfsf->fs_attr & ATTR_DIR))
      type = db_types::SCEINULL_NULL_RW;

   if(restart)
   {
      //if format is unicv.db and 
      if(settings->db_type == 0 && pfsf->fs_attr & ATTR_UNK3)
         type = db_types::SCEIFTBL_NULL_RO;
   }

  return type;
}

//pfsfile_open
//if ( pfsf->fs_attr & 0x4000 || pfsf->fs_attr & 0x8000 )
//  fa.pmi_bcl_flag |= 1u;

//isec_t is the same type as derive_keys_ctx

//this sets dctx->db_type field that can be used in isec_dbseed
void set_drv_ctx(derive_keys_ctx* dctx, pfs_image_types img_type, char* klicensee, char* type_string, char* string_id, std::uint32_t icv_version, bool restart)
{
   std::uint16_t mode_index;

   //convert image type to mode_index

   filesdb_t fl;
   fl.mode_index = img_type_to_mode_index(img_type);

   //get mode of a file

   std::uint32_t mode;
   get_file_mode(&mode, type_string, string_id);

   //convert mode to fs_attr

   pfsfile_t pfsf;

   pfsf.fs_attr = mode_to_attr(mode, is_dir(string_id), mode_index, 0);

   //use fs_attr and mode_index to convert to db_type

   dctx->db_type = flags_to_db_type(&pfsf, &fl, restart);
   dctx->icv_version = icv_version;

   //then can use all the flags

   isec_dbseed(dctx);
}

//---------------------

int setup_crypt_packet_keys(CryptEngineData* data, const derive_keys_ctx* drv_ctx)
{
   if(is_gamedata(data->mode_index))
   {
      if(isec_dbseed(drv_ctx))
      {  
         // only ro db with version > 1 
         scePfsUtilGetGDKeys2(data->dec_key, data->tweak_enc_key, data->klicensee, isec_dbseed(drv_ctx), 0x14);
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