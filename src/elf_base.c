#include "elf_base.h"
#include "log.h"
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

FILE *
open_proc_map (uint64_t pid)
{
  char proc_map_path[0x20];
  snprintf (proc_map_path, 0x20, "/proc/%ld/maps", pid);
  FILE *f = fopen (proc_map_path, "r");
  return f;
}

uint64_t
parse_elf_base (uint32_t pid)
{
  uint64_t elf_base;
  char *buf;
  uint64_t len = 0;

  FILE *f = open_proc_map (pid);
  getline (&buf, &len, f);

  elf_base = strtoull (buf, NULL, 16);
  if (elf_base == 0)
    PEXIT ("error parsing parse_elf_base");

  free (buf);
  fclose (f);

  return elf_base;
}
