#include "proc_map.h"
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
parse_maps (uint32_t pid, char *flag, char *file)
{
  uint64_t mem_start = 0;
  char *buf;
  uint64_t len = 0;

  FILE *f = open_proc_map (pid);
  getline (&buf, &len, f);

  do
    {
      if (strstr (buf, flag) && strstr (buf, file))
      {
        mem_start = strtoull (buf, NULL, 0x10);
        break;
      }
    }
  while ((getline (&buf, &len, f)) != -1);

  free (buf);
  fclose (f);

  return mem_start;
}
