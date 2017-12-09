#pragma once

#include <cstdint>

typedef int SceUID;

typedef struct CryptEngineData
{
   unsigned const char* klicensee;
   std::uint32_t files_salt; // salt from files.db is used to derive keys
   std::uint32_t unicv_page; // page is used as salt to derive keys
   std::uint16_t type;
   std::uint16_t pmi_bcl_flag;
   std::uint16_t key_id; // used for WithKeygen F00D functions. always 0.
   std::uint16_t flag0;
   std::uint32_t block_size; // file sector size specified in unicv.db

   unsigned char dec_key[0x10]; // decryption key. usually klicensee, but not always
   unsigned char iv_key[0x10]; // iv derrivation key used for decryption
   unsigned char secret[0x14]; // main secret derived from klicensee and used for checking hashes or deriving keys

}CryptEngineData;

#define CRYPT_ENGINE_ENCRYPT1 2
#define CRYPT_ENGINE_ENCRYPT2 4
#define CRYPT_ENGINE_DECRYPT 3

typedef struct CryptEngineSubctx
{
   std::uint32_t opt_code; // if 3 then decrypt, if 4 then encrypt, if 2 then encrypt
   CryptEngineData* data;
   
   unsigned char* unk_10; // unknown but probably pointer
   std::uint32_t unk_18; // unknown but probably size (based on tweak key derrivation)
   std::uint32_t nBlocksTail;
   
   std::uint32_t nBlocks; // number of file sectors corresponding to unicv page with signatures
   
   std::uint32_t sector_base; // first file sector corresponding to unicv page with signatures. used to derive iv for xts-aes
   std::uint32_t dest_offset; // not sure
   
   std::uint32_t tail_size; // size of last sector corresponding to unicv page with signatures. should be equal to file sector size in case of full page.
   
   unsigned char* signature_table; // corresponding unicv page with hmac-sha1 signatures
   
   unsigned char* work_buffer0; // input buffer to decrypt - contains file sectors corresponding to unicv page with signatures
   unsigned char* work_buffer1; // input buffer to decrypt - contains file sectors corresponding to unicv page with signatures
   
}CryptEngineSubctx;

typedef struct CryptEngineWorkCtx
{
   CryptEngineSubctx* subctx;
   int error; // set to 0 or error code after executing crypto task   
   
}CryptEngineWorkCtx;

typedef struct derive_keys_ctx
{
   std::uint32_t unk_40; // unknown
   std::uint32_t sceiftbl_version; // version of unicv
   unsigned char base_key[0x14];

}derive_keys_ctx;

void pfs_decrypt(CryptEngineWorkCtx *work_ctx);