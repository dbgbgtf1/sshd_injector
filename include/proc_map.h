#ifndef PROC_MAP
#define PROC_MAP

#include <stdint.h>
#include <sys/mman.h>

uint64_t parse_maps (uint32_t pid, char *flag);

#endif
