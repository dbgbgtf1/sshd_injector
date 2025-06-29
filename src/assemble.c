#include "log.h"
#include <keystone/keystone.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

uint8_t *
assemble (char *text, uint64_t *count)
{
  ks_engine *ks;
  unsigned char *encode;
  uint64_t size;

  if (ks_open (KS_ARCH_X86, KS_MODE_32, &ks) != KS_ERR_OK)
    PEXIT ("ks_open");

  if (ks_asm (ks, text, 0, &encode, &size, count) != KS_ERR_OK)
    PEXIT ("ks_asm")

  // close Keystone instance when done
  ks_close (ks);

  return encode;
}

void
free_ks (unsigned char *encode)
{
  ks_free (encode);
}
