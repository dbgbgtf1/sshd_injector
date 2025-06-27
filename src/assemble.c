#include "log.h"
#include <keystone/keystone.h>
#include <stdint.h>
#include <stdio.h>

void
generate_sshd_asm (uint64_t rw_gap, uint64_t rx_gap, uint64_t accept_got)
{
  char *asm_text = "";
}

void
generate_session_asm (uint64_t rw_gap, uint64_t rx_gap, uint64_t open_got)
{

}

char *
assemble (char *text)
{
  ks_engine *ks;
  size_t count;
  unsigned char *encode;
  size_t size;

  ks_open (KS_ARCH_X86, KS_MODE_32, &ks);
  PEXIT ("ks_open");

  if (ks_asm (ks, text, 0, &encode, &size, &count) != KS_ERR_OK)
    PEXIT ("ks_asm")
  else
    {
      size_t i;

      printf ("%s = ", text);
      for (i = 0; i < size; i++)
        printf ("%02x ", encode[i]);
      printf ("\n");
      printf ("Compiled: %lu bytes, statements: %lu\n", size, count);
    }

  // NOTE: free encode after usage to avoid leaking memory
  ks_free (encode);

  // close Keystone instance when done
  ks_close (ks);
}
