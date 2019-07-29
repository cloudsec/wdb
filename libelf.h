#ifndef LIBELF_H
#define LIBELF_H

#include "wdb.h"

int mmap_elf_binary(struct wdb_symbol *sym);
void unmap_elf_binary(struct wdb_symbol *sym);
int check_elf_magic(Elf64_Ehdr *elf_header);
int display_elf_header(Elf64_Ehdr *elf_header);
char *parse_ph_type(uint32_t type);
int display_program_headers(struct wdb_symbol *sym);
uint64_t get_libc_base(pid_t pid);
int read_elf_section(struct wdb_symbol *sym);
int display_section_headers(struct wdb_symbol *sym);
uint64_t fetch_symbol_addr(struct wdb_symbol *sym, char *name);
uint32_t fetch_symbol_size(struct wdb_symbol *sym, uint64_t addr);
void display_sym_table(struct wdb_symbol *sym);
void display_dsym_table(struct wdb_symbol *sym);
void display_rel_table(struct wdb_symbol *sym);
void display_rela_table(struct wdb_symbol *sym);
uint64_t fetch_address_from_rel(struct wdb_symbol *sym, char *name);
uint64_t fetch_address_from_rela(struct wdb_symbol *sym, char *name);
uint64_t fetch_address_from_reloc(struct wdb_symbol *sym, char *name);
void display_dynamic_table(struct wdb_symbol *sym);
int resolve_need_symbols(struct wdb_symbol *sym);

#endif
