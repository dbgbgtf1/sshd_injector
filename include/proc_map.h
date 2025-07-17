#ifndef PROC_MAP
#define PROC_MAP

#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>

FILE *open_proc_map (uint64_t pid);

uint64_t parse_maps (uint32_t pid, char *flag, char *file);

#endif
