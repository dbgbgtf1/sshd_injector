#include "func_offset.h"
#include "log.h"
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

uint64_t
get_func_offset (const char *func_name, const char *lib_path)
{
  if (elf_version (EV_CURRENT) == EV_NONE)
    PERROR ("elf library init");

  int fd = open (lib_path, O_RDONLY);
  if (fd == -1)
    PERROR ("open");

  Elf *elf = elf_begin (fd, ELF_C_READ, NULL);
  if (!elf)
    PERROR ("elf begin");

  size_t shstrndx;
  if (elf_getshdrstrndx (elf, &shstrndx) != 0)
    PERROR ("elf_getshdrstrndx");

  Elf_Scn *scn = NULL;
  GElf_Shdr shdr;
  while ((scn = elf_nextscn (elf, scn)) != NULL)
    {
      if (gelf_getshdr (scn, &shdr) != &shdr)
        continue;

      if (shdr.sh_type == SHT_DYNSYM || shdr.sh_type == SHT_SYMTAB)
        {
          Elf_Data *data = elf_getdata (scn, NULL);
          if (!data)
            continue;

          int symbols = shdr.sh_size / shdr.sh_entsize;
          for (int i = 0; i < symbols; ++i)
            {
              GElf_Sym sym;
              if (gelf_getsym (data, i, &sym) != &sym)
                continue;

              const char *name = elf_strptr (elf, shdr.sh_link, sym.st_name);
              if (!name)
                continue;

              if (strcmp (name, func_name) == 0)
                {
                  elf_end (elf);
                  close (fd);
                  return (unsigned long)sym.st_value;
                }
            }
        }
    }

  elf_end (elf);
  close (fd);
  return 0;
}
