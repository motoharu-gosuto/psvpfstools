#pragma once

int icv_set_hmac_sw(unsigned char *dst, const unsigned char *key, const unsigned char *src, int size);

int icv_set_sw(unsigned char *dst, const unsigned  char *src, int size);

int icv_contract(unsigned char *result, const unsigned char *left_hash, const unsigned char *right_hash);