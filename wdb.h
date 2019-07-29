#ifndef WDB_H
#define WDB_H

#include <stdint.h>
#include <elf.h>

#define MAX_ELF_NUM				32
#define MAX_REL_NUM				32

#define MAX_BREAKPOINT_NUM			64

#define DEFAULT_LIBC_PATH			"/lib64"

struct wdb_breakpoint {
	char bp_symbol[64];
	uint64_t bp_addr;
	long bp_orig_data;
}wdb_bp[MAX_BREAKPOINT_NUM];

int bp_bitmap[MAX_BREAKPOINT_NUM];

struct wdb_symbol {
	int mmap_fd;				/* fd of binary. */
	int mmap_size;				/* file size of binary. */
	char *elf_path;				/* point to elf binary path. */
	void *base_addr;			/* mmap base address. */
	void *libc_addr;			/* the libc address of child process. */
	Elf64_Ehdr *elf_header;			/* section of elf header. */
	Elf64_Phdr *ph_header;			/* section of program header. */
	Elf64_Shdr *sh_header;			/* section of section header. */
	Elf64_Shdr *sym_table;			/* section of symbol table. */
	Elf64_Shdr *dsym_table;			/* section of dynmic symbol table. */
	Elf64_Shdr *dyn_table;			/* section of dynmic table. */
	Elf64_Shdr *plt_table;			/* section of plt table. */
	Elf64_Shdr *rel_table[MAX_REL_NUM];	/* An object file may have multiple relocation sections. */
	Elf64_Shdr *rela_table[MAX_REL_NUM];	/* relocate table explicit addends. */
	int rel_idx;				/* index of rel table. */
	int rela_idx;				/* index of rela table. */
	void *strtab_mem;			/* symbol table strings. */
	void *dynstr_mem;			/* dynmic symbol table strings. */
	void *shstrtab_mem;			/* section table name strings. */
}wdb_syms[MAX_ELF_NUM];

int wdb_sym_idx;

void wdb_show_regs(void);
uint64_t get_reg_value(char *reg_name);
void print_bps(void);
int alloc_bp(void);
void free_bp(int n);
int search_bp_symbol(char *symbol);
int search_bp_address(uint64_t addr);
int delete_bp_array(int idx);

uint64_t wdb_symbol_addr(char *sym_name);
int32_t wdb_symbol_size(uint64_t sym_addr);
int wdb_fixup_libc_address(pid_t pid);
int wdb_delete_breakpoint(int n, int flag);
int wdb_restore_breakpoint(void);
int wdb_set_breakpoint(struct wdb_breakpoint *bp);
int wdb_set_breakpoints(void);
int wdb_wait_breakpoints(void);
int wdb_step_instruction(void);
int wdb_ni_instruction(void);
int wdb_got_control(int flag);
int wdb_attach_program(void);
int wdb_detach_program(void);
int ptrace_read_memory(pid_t pid, uint64_t addr, void *buf, int size);

#endif
