#include "PfsCryptEngine.h"

#include <string>

#include "SceSblSsMgrForDriver.h"
#include "SceKernelUtilsForDriver.h"
#include "PfsCryptEngineBase.h"
#include "PfsCryptEngineSelectors.h"

//----------------------

void verify_step(CryptEngineWorkCtx* crypt_ctx, int64_t tweak_key, int bitSize, int size, unsigned char* source)
{
   // variable mapping

   if((crypt_ctx->subctx->data->flag0 << 0x12) < 0)
      return; // this does not terminate crypto task (local exit)
   
   if((crypt_ctx->subctx->data->flag0 << 0x10) < 0)
      return; // this does not terminate crypto task (local exit)

   if((crypt_ctx->subctx->data->pmi_bcl_flag & 0x20) != 0)
      return; // this does not terminate crypto task (local exit)

   if((bitSize > 0x1F) || ((0xC0000B03 & (1 << bitSize)) == 0))
   {
      if((crypt_ctx->subctx->data->pmi_bcl_flag & 0x41) != 0x41)
      {
         if(crypt_ctx->subctx->nBlocks != 0)
         {
            int counter = 0;

            unsigned char* source_base = source;
            unsigned char* signatures_base = crypt_ctx->subctx->signature_table;
                     
            unsigned char bytes14[0x14] = {0};

            do
            {
               int size_arg = crypt_ctx->subctx->data->block_size;
               SceSblSsMgrForDriver_sceSblSsMgrHMACSHA1ForDriver(source_base, bytes14, size_arg, crypt_ctx->subctx->data->secret, 0, 1, 0);
                        
               int ver_res = memcmp(signatures_base, bytes14, 0x14);

               //if verify is not successful and flag is not specified
               if((ver_res != 0) && ((crypt_ctx->subctx->data->pmi_bcl_flag & 9) != 1))
               {
                  crypt_ctx->error = 0x80140F02;
                  return; // this should terminate crypto task (global exit)
               }
                        
               counter = counter + 1;

               source_base = source_base + crypt_ctx->subctx->data->block_size;
               signatures_base = signatures_base + 0x14;
            }
            while(counter != crypt_ctx->subctx->nBlocks);
         }
      }
   }
   else
   {
      if((crypt_ctx->subctx->data->pmi_bcl_flag & 0x41) != 0x41)
      {
         int salt = (int)tweak_key;
                  
         if(crypt_ctx->subctx->nBlocks != 0)
         {
            uint32_t counter = 0;
            uint32_t bytes_left = size;

            unsigned char* source_base = source;
            unsigned char* signatures_base = crypt_ctx->subctx->signature_table;

            unsigned char digest[0x14] = {0};
            unsigned char bytes14[0x14] = {0};

            do
            {
               SceKernelUtilsForDriver_sceHmacSha1DigestForDriver(crypt_ctx->subctx->data->secret, 0x14, (unsigned char*)&salt, 4, digest);

               int size_arg = (crypt_ctx->subctx->data->block_size < bytes_left) ? crypt_ctx->subctx->data->block_size : bytes_left;
               SceSblSsMgrForDriver_sceSblSsMgrHMACSHA1ForDriver(source_base, bytes14, size_arg, digest, 0, 1, 0);
                        
               int ver_res = memcmp(signatures_base, bytes14, 0x14);
                        
               //if verify is not successful and flag is not specified
               if((ver_res != 0) && ((crypt_ctx->subctx->data->pmi_bcl_flag & 9) != 1))
               {
                  crypt_ctx->error = 0x80140F02;
                  return; // this should terminate crypto task (global exit)
               }
                        
               counter = counter + 1;
               bytes_left = bytes_left - crypt_ctx->subctx->data->block_size;

               source_base = source_base + crypt_ctx->subctx->data->block_size;
               signatures_base = signatures_base + 0x14;

               salt = salt + 1;
            }
            while(counter != crypt_ctx->subctx->nBlocks);
         }
      }
   }
}

void work_3_step0(CryptEngineWorkCtx* crypt_ctx, int64_t tweak_key, int bitSize, int size, unsigned char* buffer)
{
   int tweak_key0 = (int)tweak_key;
   int tweak_key1 = (int)(tweak_key >> 0x20);

   // variable mapping

   unsigned const char* key = crypt_ctx->subctx->data->dec_key;
   unsigned const char* subkey_key = crypt_ctx->subctx->data->iv_key;
   
   //------------------------------

   //conflicts with decryption
   /*
   if(((int)crypt_ctx->subctx->data->flag0 & 0x4000) == 0)
   {
      crypt_ctx->error = 0;
      return; // this should terminate crypto task (global exit)
   }
   */

   if((crypt_ctx->subctx->data->flag0 << 0x10) < 0)
   {
      crypt_ctx->error = 0;
      return; // this should terminate crypto task (global exit)
   }

   if((crypt_ctx->subctx->data->pmi_bcl_flag & 0x41) == 0x41)
   {
      crypt_ctx->error = 0;
      return; // this should terminate crypto task (global exit)
   }

   if(crypt_ctx->subctx->nBlocks == 0)
   {
      crypt_ctx->error = 0;
      return; // this should terminate crypto task (global exit)
   }

   //============== remove first encryption layer ? =========================

   int offset = 0;
   int counter = 0;

   if((bitSize > 0x1F) || ((0xC0000B03 & (1 << bitSize)) == 0))
   {   
      do
      {
         pfs_decrypt_sw(key, subkey_key, 0x80, tweak_key0 + offset, tweak_key1 + 0, crypt_ctx->subctx->data->block_size, crypt_ctx->subctx->data->block_size, buffer + offset, buffer + offset, crypt_ctx->subctx->data->pmi_bcl_flag);

         counter = counter + 1;
         offset = offset + crypt_ctx->subctx->data->block_size;
      }
      while(counter != crypt_ctx->subctx->nBlocks);
   }
   else
   {
      uint32_t bytes_left = size;
   
      do
      {
         int size_arg = ((crypt_ctx->subctx->data->block_size < bytes_left) ? crypt_ctx->subctx->data->block_size : bytes_left);
         pfs_decrypt_hw(key, subkey_key, tweak_key0 + offset, tweak_key1 + 0, size_arg, crypt_ctx->subctx->data->block_size, buffer + offset, buffer + offset, crypt_ctx->subctx->data->pmi_bcl_flag, crypt_ctx->subctx->data->key_id);

         bytes_left = bytes_left - crypt_ctx->subctx->data->block_size;
         offset = offset + crypt_ctx->subctx->data->block_size;
         counter = counter + 1;
      }
      while(counter != crypt_ctx->subctx->nBlocks);
   }

   crypt_ctx->error = 0;
   return; // this should terminate crypto task (global exit)
}

void work_3_step1(CryptEngineWorkCtx* crypt_ctx, int bitSize, unsigned char* buffer)
{
   // variable mapping

   unsigned const char* key = crypt_ctx->subctx->data->dec_key;
   unsigned const char* subkey_key = crypt_ctx->subctx->data->iv_key;

   unsigned char* output_dst = crypt_ctx->subctx->unk_10 + ((crypt_ctx->subctx->data->block_size * crypt_ctx->subctx->unk_18) - crypt_ctx->subctx->dest_offset);
   unsigned char* output_src = buffer + (crypt_ctx->subctx->data->block_size * crypt_ctx->subctx->unk_18);
   int output_size = crypt_ctx->subctx->data->block_size * crypt_ctx->subctx->nBlocksTail;

   //========== process block part of source buffer ? ========================

   if(crypt_ctx->subctx->unk_18 == 0)
   {
      int tweak_key0_block = crypt_ctx->subctx->data->block_size * crypt_ctx->subctx->sector_base;
      int tweak_key1_block = (int)crypt_ctx->subctx->data->flag0 & 0x4000;

      if(tweak_key1_block == 0)
      {
         if((crypt_ctx->subctx->data->flag0 << 0x10) >= 0)
         {
            if((crypt_ctx->subctx->data->pmi_bcl_flag & 0x41) != 0x41)
            {
               if((bitSize > 0x1F) || ((0xC0000B03 & (1 << bitSize)) == 0))
               {
                  pfs_decrypt_sw(key, subkey_key, 0x80, tweak_key0_block, tweak_key1_block, crypt_ctx->subctx->data->block_size, crypt_ctx->subctx->data->block_size, buffer, buffer, crypt_ctx->subctx->data->pmi_bcl_flag);
               }
               else
               {
                  pfs_decrypt_hw(key, subkey_key, tweak_key0_block, tweak_key1_block, crypt_ctx->subctx->data->block_size, crypt_ctx->subctx->data->block_size, buffer, buffer, crypt_ctx->subctx->data->pmi_bcl_flag, crypt_ctx->subctx->data->key_id);
               }
            }
         }
      }  
   }

   //========= copy result to output buffer if source buffer had no tail ? ============

   uint32_t some_value = crypt_ctx->subctx->nBlocksTail + crypt_ctx->subctx->unk_18;
   
   if((some_value >= crypt_ctx->subctx->nBlocks))
   {
      if(output_src != output_dst)
         memcpy(output_dst, output_src, output_size);
      crypt_ctx->error = 0;
      return; // this should terminate crypto task (global exit)
   }

   if(((int)crypt_ctx->subctx->data->flag0 & 0x4000) != 0)
   {   
      if(output_src != output_dst)
         memcpy(output_dst, output_src, output_size);
      crypt_ctx->error = 0;
      return; // this should terminate crypto task (global exit)
   }

   //=========== process tail part of source buffer ? ===============================
   
   if((crypt_ctx->subctx->data->flag0 << 0x10) >= 0)
   {   
      if((crypt_ctx->subctx->data->pmi_bcl_flag & 0x41) != 0x41)
      {
         int tweak_key0_tail = crypt_ctx->subctx->data->block_size * (crypt_ctx->subctx->sector_base + (crypt_ctx->subctx->nBlocks - 1));
         int tweak_key1_tail = (int)crypt_ctx->subctx->data->flag0 & 0x4000;

         unsigned char* tail_buffer = buffer + crypt_ctx->subctx->data->block_size * (crypt_ctx->subctx->nBlocks - 1);

         if((bitSize > 0x1F) || ((0xC0000B03 & (1 << bitSize)) == 0))
         {
            pfs_decrypt_sw(key, subkey_key, 0x80, tweak_key0_tail, tweak_key1_tail, crypt_ctx->subctx->data->block_size, crypt_ctx->subctx->data->block_size, tail_buffer, tail_buffer, crypt_ctx->subctx->data->pmi_bcl_flag);
         }
         else
         {
            int size_arg = (crypt_ctx->subctx->data->block_size <= crypt_ctx->subctx->tail_size) ? crypt_ctx->subctx->data->block_size : crypt_ctx->subctx->tail_size;
            pfs_decrypt_hw(key, subkey_key, tweak_key0_tail, tweak_key1_tail, size_arg, crypt_ctx->subctx->data->block_size, tail_buffer, tail_buffer, crypt_ctx->subctx->data->pmi_bcl_flag, crypt_ctx->subctx->data->key_id);
         }
      }
   }

   //========= copy tail result to output buffer ? ===========================
   
   if((crypt_ctx->subctx->data->flag0 << 0x10) < 0)
   {
      if(output_src != output_dst)
         memcpy(output_dst, output_src, output_size);
      crypt_ctx->error = 0;
      return; // this should terminate crypto task (global exit)
   }

   if((crypt_ctx->subctx->data->pmi_bcl_flag & 0x41) == 0x41)
   {
      if(output_src != output_dst)
         memcpy(output_dst, output_src, output_size);
      crypt_ctx->error = 0;
      return; // this should terminate crypto task (global exit)
   }

   //============== remove second encryption layer ? =========================

   //seed derrivation is quite same to derrivation in first layer

   int seed_root = crypt_ctx->subctx->data->block_size * (crypt_ctx->subctx->unk_18 + crypt_ctx->subctx->sector_base);
   int tweak_key0_end = seed_root >> 0x20;
   int tweak_key1_end = seed_root >> 0x20;
   
   if(crypt_ctx->subctx->nBlocksTail == 0)
   {
      crypt_ctx->error = 0;
      return; // this should terminate crypto task (global exit)
   }

   int offset = 0;
   int counter = 0;

   if((bitSize > 0x1F) || ((0xC0000B03 & (1 << bitSize)) == 0))
   {
      do
      {
         pfs_decrypt_sw(key, subkey_key, 0x80, tweak_key0_end + offset, tweak_key1_end + 0, crypt_ctx->subctx->data->block_size, crypt_ctx->subctx->data->block_size, output_src + offset, output_dst + offset, crypt_ctx->subctx->data->pmi_bcl_flag);

         offset = offset + crypt_ctx->subctx->data->block_size;
         counter = counter + 1;
      }
      while(counter != crypt_ctx->subctx->nBlocksTail);

      crypt_ctx->error = 0;
      return; // this should terminate crypto task (global exit)
   }
   else
   {
      uint32_t bytes_left = output_size;
      
      do
      {
         int size_arg = (crypt_ctx->subctx->data->block_size <= bytes_left) ? crypt_ctx->subctx->data->block_size : bytes_left;
         pfs_decrypt_hw(key, subkey_key, tweak_key0_end + offset, tweak_key1_end + 0, size_arg, crypt_ctx->subctx->data->block_size, output_src + offset, output_dst + offset, crypt_ctx->subctx->data->pmi_bcl_flag, crypt_ctx->subctx->data->key_id);

         offset = offset + crypt_ctx->subctx->data->block_size;
         bytes_left = bytes_left - crypt_ctx->subctx->data->block_size;
         counter = counter + 1;
      }
      while(counter != crypt_ctx->subctx->nBlocksTail);
   
      crypt_ctx->error = 0;
      return; // this should terminate crypto task (global exit)
   }
}

//TODO CHECK:
//int var_8C = (int)crypt_ctx->subctx->data->type - 2; // this does not correlate with derive_keys_from_klicensee_219B4A0
//int some_flag_base = (uint32_t)(data->pmi_bcl_flag - 2);
//int some_flag = 0xC0000B03 & (1 << some_flag_base);

//however i have double checked the code and it is correct in both places

void crypt_engine_work_3(CryptEngineWorkCtx* crypt_ctx)
{
   int64_t tweak_key= crypt_ctx->subctx->sector_base;

   int bitSize = (int)crypt_ctx->subctx->data->type - 2; // this does not correlate with derive_keys_from_klicensee_219B4A0
   int total_size = (crypt_ctx->subctx->data->block_size) * ((crypt_ctx->subctx->nBlocks) - 1) + (crypt_ctx->subctx->tail_size);

   unsigned char* work_buffer;
   if((bitSize > 0x1F) || ((0xC0000B03 & (1 << bitSize)) == 0))
      work_buffer = crypt_ctx->subctx->work_buffer0;
   else
      work_buffer = crypt_ctx->subctx->work_buffer1;

   //verifies table of hashes ?
   verify_step(crypt_ctx, tweak_key, bitSize, total_size, work_buffer);

   //need to add this check since dec functionality is now split into several functions
   if(crypt_ctx->error < 0)
      return;

   if(crypt_ctx->subctx->nBlocksTail == 0)
   {
      //immediately decrypts everything in while loop
      work_3_step0(crypt_ctx, tweak_key, bitSize, total_size, work_buffer);
   }
   else
   {
      //first - decrypts block part with single call
      //second - decrypts tail part with single call
      //third - decrypts everything in while loop
      work_3_step1(crypt_ctx, bitSize, work_buffer);
   }
}

void crypt_engine_work_2_4(CryptEngineWorkCtx * crypt_ctx, CryptEngineSubctx* r10)
{

}

void pfs_decrypt(CryptEngineWorkCtx *work_ctx)
{
   switch(work_ctx->subctx->opt_code)
   {
   case 2:
      crypt_engine_work_2_4(work_ctx, work_ctx->subctx);
      break;
   case 3:
      crypt_engine_work_3(work_ctx);
      break;
   case 4:
      crypt_engine_work_2_4(work_ctx, work_ctx->subctx);
      break;
   default:
      break;
   }
}