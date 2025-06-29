#include "proc_map.h"
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
  // sprintf (proc_map_path, "/proc/%d/maps", pid);
  FILE *f = fopen (proc_map_path, "r");
  return f;
}

uint64_t
parse_maps (uint32_t pid, char *flag)
{
  uint64_t sshd_base;
  char *buf;
  uint64_t len = 0;

  FILE *f = open_proc_map (pid);
  getline (&buf, &len, f);

  sshd_base = strtoull (buf, NULL, 16);
  if (sshd_base == 0)
    PEXIT ("error parsing parse_sshd_base");

  do
    {
      if (strstr (buf, flag))
        break;
    }
  while ((getline (&buf, &len, f)) != -1);

  free (buf);
  fclose (f);

  return sshd_base;
}
