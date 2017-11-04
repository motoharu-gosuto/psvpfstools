#pragma once

struct CryptEngineData;
struct derive_keys_ctx;

int DerivePfsKeys(CryptEngineData* data, const derive_keys_ctx* drv_ctx);