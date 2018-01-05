#pragma once

struct CryptEngineData;
struct derive_keys_ctx;

int setup_crypt_packet_keys(CryptEngineData* data, const derive_keys_ctx* drv_ctx);