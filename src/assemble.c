#include "assemble.h"
#include "log.h"
#include <keystone/keystone.h>
#include <stddef.h>
#include <stdint.h>

uint8_t *
assemble (char *text)
{
  ks_engine *ks;
  unsigned char *encode;
  uint64_t count;
  uint64_t size;

  if (ks_open (KS_ARCH_X86, KS_MODE_64, &ks) != KS_ERR_OK)
    PEXIT ("ks_open");

  if (ks_asm (ks, text, 0, &encode, &size, &count) != KS_ERR_OK)
    PEXIT ("ks_asm")

  ks_close (ks);

  return encode;
}

void
free_ks (unsigned char *encode)
{
  ks_free (encode);
}
