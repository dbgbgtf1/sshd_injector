#ifndef GOT_OFFSET
#define GOT_OFFSET

#include <stdint.h>
uint64_t get_got_offset (const char *elf_file, const char *func_name);

#endif
