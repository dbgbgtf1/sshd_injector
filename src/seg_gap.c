#include "seg_gap.h"
#include "log.h"
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <unistd.h>

uint64_t
get_seg_gap (const char *elf_file, int flag)
{
  int fd;
  Elf *elf;
  uint64_t phnum;
  GElf_Phdr phdr;
  uint64_t i;

  if (elf_version (EV_CURRENT) == EV_NONE)
    PERROR ("elf_version");

  if ((fd = open (elf_file, O_RDONLY)) < 0)
    {
      printf ("open: %s\n", elf_file);
      PERROR ("");
    }

  if ((elf = elf_begin (fd, ELF_C_READ, NULL)) == NULL)
    PERROR ("elf_begin");

  if (elf_getphdrnum (elf, &phnum) != 0)
    PERROR ("elf_getphdrnum");

  for (i = 0; i < phnum; i++)
    {
      if (gelf_getphdr (elf, i, &phdr) != &phdr)
        PERROR ("gelf_getphdr");

      if (phdr.p_type == PT_LOAD && phdr.p_flags == (unsigned int)flag)
        {
          int result = phdr.p_memsz + phdr.p_vaddr;
          elf_end (elf);
          close (fd);
          return ((result & ~0x7) + 8);
        }
    }

  PEXIT ("elf parse error");
}
