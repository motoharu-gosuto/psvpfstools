#pragma once

struct CryptEngineData;
struct derive_keys_ctx;

int derive_data_ctx_keys(CryptEngineData* data, const derive_keys_ctx* drv_ctx);