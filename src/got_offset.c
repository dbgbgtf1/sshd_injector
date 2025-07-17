#include "got_offset.h"
#include "log.h"
#include <assert.h>
#include <fcntl.h>
#include <gelf.h>
#include <string.h>
#include <unistd.h>

uint64_t
get_got_offset (const char *elf_file, const char *func_name)
{
  if (elf_version (EV_CURRENT) == EV_NONE)
    PERROR ("elf library init");

  int fd = open (elf_file, O_RDONLY);
  if (fd == -1)
    {
      printf ("open: %s\n", elf_file);
      PERROR ("");
    }

  Elf *elf = elf_begin (fd, ELF_C_READ, NULL);
  if (!elf)
    PERROR ("elf begin");

  uint64_t shstrndx;
  if (elf_getshdrstrndx (elf, &shstrndx) != 0)
    PERROR ("elf_getshdrstrndx");

  Elf_Scn *scn = NULL;
  GElf_Shdr shdr;

  Elf_Scn *dynsym_scn = NULL, *reloc_scn = NULL;
  Elf_Data *dynsym_data = NULL, *reloc_data = NULL;
  const char *dynstr = NULL;

  while ((scn = elf_nextscn (elf, scn)) != NULL)
    {
      gelf_getshdr (scn, &shdr);
      const char *section_name = elf_strptr (elf, shstrndx, shdr.sh_name);

      if (strcmp (section_name, ".dynsym") == 0)
        {
          dynsym_scn = scn;
          dynsym_data = elf_getdata (scn, NULL);
        }
      else if (strcmp (section_name, ".dynstr") == 0)
        dynstr = elf_getdata (scn, NULL)->d_buf;
      else if (strcmp (section_name, ".rela.dyn") == 0
               || strcmp (section_name, ".rela.plt") == 0)
        {
          reloc_scn = scn;
          reloc_data = elf_getdata (scn, NULL);
        }
    }

  if (!dynsym_scn || !dynstr || !reloc_scn)
    PERROR ("Missing sections in elf");

  uint64_t symbol_count = dynsym_data->d_size / sizeof (GElf_Sym);

  int target_sym_index = -1;

  for (uint64_t i = 0; i < symbol_count; ++i)
    {
      GElf_Sym sym;
      gelf_getsym (dynsym_data, i, &sym);
      const char *name = &dynstr[sym.st_name];
      if (strcmp (name, func_name) == 0)
        {
          target_sym_index = i;
          break;
        }
    }

  if (target_sym_index < 0)
    PEXIT ("function not found in .dynsym");

  uint64_t reloc_count = reloc_data->d_size / sizeof (GElf_Rela);
  for (uint64_t i = 0; i < reloc_count; ++i)
    {
      GElf_Rela rela;
      gelf_getrela (reloc_data, i, &rela);
      int sym_index = GELF_R_SYM (rela.r_info);
      int r_type = GELF_R_TYPE (rela.r_info);

      if (sym_index == target_sym_index
          && (r_type == R_X86_64_JUMP_SLOT || r_type == R_X86_64_GLOB_DAT))
        {
          uint64_t got_addr = rela.r_offset;
          elf_end (elf);
          close (fd);
          return got_addr;
        }
    }

  PEXIT ("got not found in relocations\n");
}
