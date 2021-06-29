#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "sm2_math.c"

int LLVMFuzzerTestOneInput(uint8_t *data, size_t size) {
  int total_size = sizeof(SM2_KEY) + 32 + sizeof(SM2_SIGNATURE);
  if (size < total_size)
    return 1;
  const SM2_KEY* key = (const SM2_KEY*)data;
  const uint8_t* digest = data + sizeof(SM2_KEY);
  const SM2_SIGNATURE* sig = data + sizeof(SM2_KEY) + 32;
  int ret = sm2_do_verify(key, digest, sig);
  return 0;
}
