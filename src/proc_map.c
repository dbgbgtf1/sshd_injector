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
  FILE *f = fopen (proc_map_path, "r");
  if (f == NULL)
    {
      printf ("fopen: %s\n", proc_map_path);
      PERROR ("");
    }
  return f;
}

uint64_t
parse_maps (uint32_t pid, char *flag, char *file)
{
  uint64_t mem_start = 0;
  char *buf;
  uint64_t len = 0;

  FILE *f = open_proc_map (pid);
  while ((getline (&buf, &len, f)) != -1)
    {
      if (strstr (buf, flag) && strstr (buf, file))
        {
          mem_start = strtoull (buf, NULL, 0x10);
          break;
        }
    }

  free (buf);
  fclose (f);

  if (mem_start == 0)
    {
      printf ("parse_maps: %s %s not found", flag, file);
      exit (0);
    }
  return mem_start;
}
