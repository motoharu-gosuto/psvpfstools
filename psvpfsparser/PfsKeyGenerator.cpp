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

//does this encode sce_ng_pfs_file_types ?

struct mode_to_attr_entry_t
{
  int unk0;
  std::uint16_t unk4;
  std::uint16_t unk6;
};

mode_to_attr_entry_t genericMode2AttrTbl[4] = 
{
   {0x000, 0x0006, 0}, 
   {0x100, 0x0001, 0}, //ro
   {0x080, 0x0000, 0}, 
   {0x180, 0x0000, 0}, //rw
};

mode_to_attr_entry_t specificMode2AttrTbl[4] = 
{
   {0x000000, 0x0000, 0}, 
   {0x100000, 0x4000, 0}, 
   {0x200000, 0x2000, 0}, 
   {0x300000, 0x6000, 0}
};

int scePfsACSetFSAttrByMode(std::uint32_t mode, std::uint16_t* flag0)
{
  std::uint16_t prop0 = 0;
  std::uint16_t prop1 = 0;

  int i;
  
  for(i = 0; i < 4; ++i)
  {
    if(genericMode2AttrTbl[i].unk0 == (mode & 0x180))
    {
      prop1 = genericMode2AttrTbl[i].unk4;
      break;
    }
  }

  if(i == 4)
    return -9;

  int j;

  for(j = 0; j < 4; ++j)
  {
    if(specificMode2AttrTbl[j].unk0 == (mode & 0x300000))
    {
      prop0 = specificMode2AttrTbl[j].unk4;
      break;
    }
  }

  if(j == 4)
    return -9;

  *flag0 = prop1 | prop0;

  return 0;
}

std::uint16_t pfsfile_open(std::uint32_t mode)
{
   std::uint16_t flag0;

   scePfsACSetFSAttrByMode(mode, &flag0);

   return flag0;
}

//flag0 0x1000 is assigned only when mode has flag 0x1000 and modeindex == ac_root and nid == 0

// if ( mode & 0x1000 && (pfsf->files->mode_index != 4 || nid > 1) )
//    return 0x8014601C;

std::uint16_t pfsfile_mkdir(std::uint32_t mode)
{
   std::uint16_t flag0;

   scePfsACSetFSAttrByMode(mode, &flag0);

   flag0 |= 0x8000;

   if(mode & 0x1000)
      flag0 |= 0x1000;

   return flag0;
}

int is_dir(char* string_id)
{
  return !strcmp(string_id, "dir") || !strcmp(string_id, "aciddir");
}

#define MODE_RW  0x180
#define MODE_RO  0x100

#define MODE_ACIDDIR 0x9000
#define MODE_DIR     0x8000
#define MODE_NPFS    0x300000
#define MODE_NENC    0x100000
#define MODE_NICV    0x200000

int get_file_mode(std::uint32_t* mode, char* type_string, char* string_id)
{
   *mode = 0;
   if(!strcmp(type_string, "") || !strcmp(type_string, "rw"))
   {
      *mode |= MODE_RW;
   }
   else if(!strcmp(type_string, "ro"))
   {
      *mode |= MODE_RO;
   }
   else if(!strcmp(type_string, "sys"))
   {
      *mode = *mode;
   }
   else
   {
      std::runtime_error("invalid type_string");
   }
  
   if(!strcmp(string_id, ""))
   {
      return 0;
   }
   else if(!strcmp(string_id, "aciddir"))
   {
      *mode |= MODE_ACIDDIR;
      return 0;
   }
   else if(!strcmp(string_id, "dir"))
   {
      *mode |= MODE_DIR;
      return 0;
   }
   else if(!strcmp(string_id, "npfs"))
   {
      *mode |= MODE_NPFS;
      return 0;
   }
   else if(!strcmp(string_id, "nenc"))
   {
      *mode |= MODE_NENC;
      return 0;
   }
   else if(!strcmp(string_id, "nicv"))
   {
      *mode |= MODE_NICV;
      return 0;
   }
   else
   {
      std::runtime_error("invalid string_id");
   }
}

//---------------------

//flag map - derrivation up to this point

struct filesdb_t
{
   std::uint16_t pmi_bcl_flag;
   std::uint16_t mode_index;
};

struct pfsfile_t
{
   std::uint16_t flag0;
};

std::uint32_t flags_to_unk_40(pfsfile_t* pfsf, filesdb_t* fl, bool restart)
{
   pfs_mode_settings* settings = scePfsGetModeSetting(fl->mode_index);

   std::uint32_t unk40 = settings->unk_4;

   if(settings->unk_4 == 1 && (pfsf->flag0 & 0x2000 || pfsf->flag0 & 0x8000))
      unk40 = 2;

   if(restart)
   {
      if(settings->unk_4 == 0 && pfsf->flag0 & 0x400 )
         unk40 = 3;
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

   if(is_dir(string_id))
   {
      pfsf.flag0 = pfsfile_mkdir(mode);
   }
   else
   {
      pfsf.flag0 = pfsfile_open(mode);
   }

   //use flag0 and mode_index to convert to unk40

   dctx->unk_40 = flags_to_unk_40(&pfsf, &fl, restart);
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