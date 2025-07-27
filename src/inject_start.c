#include "inject_start.h"
#include "log.h"
#include "proc_map.h"
#include "seg_gap.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

uint64_t
new_rx_gap (char *buf)
{
  char *file_start = strstr (buf, "/usr");
  *strchr (buf, '\n') = '\0';
  if (file_start == NULL)
    return 0;

  uint64_t rx_gap = 0x1000 - (get_seg_gap (file_start, 5) % 0x1000);
  return rx_gap;
}

uint64_t
inject_start (int32_t pid, uint64_t code_size)
{
  printf ("[INFO]: the code size is 0x%lx\n", code_size);

  char *buf;
  uint64_t len = 0;
  FILE *f = open_proc_map (pid);

  while ((getline (&buf, &len, f)) != -1)
    {
      if (!strstr (buf, "r-xp"))
        continue;

      uint64_t rx_gap = new_rx_gap (buf);
      if (code_size > rx_gap)
        continue;
      char *end;
      uint64_t rx_start = strtoull (buf, &end, 0x10);
      uint64_t rx_end = strtoull (end + 1, NULL, 0x10);
      printf ("[INFO]: inject rx seg \n%s\n", buf);
      printf ("[INFO]: rx_gap: 0x%lx\n", rx_gap);
      printf ("[INFO]: inject to 0x%lx\n", rx_end - rx_gap);
      return rx_end - rx_gap;
    }

  PEXIT ("[ERROR]: no enough rx to inject the code");
}
