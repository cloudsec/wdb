#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>
#include <sys/stat.h>
#include <sys/mman.h>


#include "wdb.h"
#include "libelf.h"

int mmap_elf_binary(struct wdb_symbol *sym)
{
        struct stat f_stat;
        int fd;

        fd = open(sym->elf_path, O_RDONLY);
        if (fd == -1) {
                perror("open");
                return -1;
        }

        if (stat(sym->elf_path, &f_stat) == -1) {
                perror("stat");
                goto out;
        }

        sym->mmap_fd = fd;
        sym->mmap_size = f_stat.st_size;

        sym->base_addr = mmap(NULL, sym->mmap_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (sym->base_addr == MAP_FAILED) {
                perror("mmap");
                goto out_map;
        }

	sym->elf_header = (Elf64_Ehdr *)sym->base_addr;
	sym->ph_header = (Elf64_Phdr *)(sym->base_addr + sym->elf_header->e_phoff);
	sym->sh_header = (Elf64_Shdr *)(sym->base_addr + sym->elf_header->e_shoff);

        sym->shstrtab_mem = (void *)(sym->base_addr + 
				sym->sh_header[sym->elf_header->e_shstrndx].sh_offset);

        close(fd);
        return 0;

out_map:
        munmap(sym->base_addr, sym->mmap_size);
out:
        close(fd);
        return -1;
}

void unmap_elf_binary(struct wdb_symbol *sym)
{
        munmap(sym->base_addr, sym->mmap_size);
        close(sym->mmap_fd);
}

int check_elf_magic(Elf64_Ehdr *elf_header)
{
	if (memcmp(elf_header->e_ident, ELFMAG, SELFMAG)) {
		fprintf(stderr, "wrong elf magic.\n");
		return -1;
	}

	if (elf_header->e_ident[EI_CLASS] != ELFCLASS64) {
		fprintf(stderr, "not support 32bit elf format.\n");
		return -1;
	}

	return 0;
}

int display_elf_header(Elf64_Ehdr *elf_header)
{
	int i;

	printf("%-16s\t", "magic:");
	for (i = 0; i < EI_NIDENT; i++)
		printf("%02x ", elf_header->e_ident[i]);
	printf("\n");

	switch (elf_header->e_ident[EI_CLASS]) {
	case ELFCLASS32:
		printf("%-16s\t32bit\n", "class:");
		break;
	case ELFCLASS64:
		printf("%-16s\t64bit\n", "class:");
		break;
	default:
		printf("wrong class type.\n");
		return -1;
	}

	switch (elf_header->e_ident[EI_DATA]) {
	case ELFDATA2LSB:
		printf("%-16s\tTwo's complement, little-endian.\n", "data:");
		break;
	case ELFDATA2MSB:
		printf("%-16s\tTwo's complement, big-endian.\n", "data:");
		break;
	default:
		printf("wrong data type.\n");
		return -1;
	}
	
	printf("%-16s\t%d\n", "version:", elf_header->e_ident[EI_VERSION]);

	switch (elf_header->e_ident[EI_OSABI]) {
	case ELFOSABI_LINUX:
		printf("%-16s\tLinux ABI.\n", "osabi:");
		break;
	case ELFOSABI_SYSV:
		printf("%-16s\tUNIX System V ABI.\n", "osabi:");
		break;
	case ELFOSABI_ARM:
		printf("%-16s\tARM architecture ABI.\n", "osabi:");
		break;
	default:
		printf("unkonw osabi.\n");
		return -1;
	}
		
	switch (elf_header->e_type) {
	case ET_REL:
		printf("%-16s\trelocatable file.\n", "type:");
		break;
	case ET_EXEC:
		printf("%-16s\texecutable file.\n", "type:");
		break;
	case ET_DYN:
		printf("%-16s\tshared object.\n", "type:");
		break;
	case ET_CORE:
		printf("%-16s\tcore file.\n", "type:");
		break;
	default:
		printf("unkonw elf type.\n");
		return -1;
	}

	switch (elf_header->e_machine) {
	case EM_X86_64:
		printf("%-16s\tAMD x86-64.\n", "machine:");
		break;
	case EM_ARM:
		printf("%-16s\tAdvanced RISC Machines.\n", "machine:");
		break;
	default:
		printf("unkonw elf machine type.\n");
		return -1;
	}

	printf("%-16s\t%d\n", "version:", elf_header->e_version);
	printf("%-16s\t0x%x (program entry address)\n", "entry:", elf_header->e_entry);
	printf("%-16s\t0x%x (program header table offset)\n", "phoff:", elf_header->e_phoff);
	printf("%-16s\t0x%x (section header table offset)\n", "shoff:", elf_header->e_shoff);
	printf("%-16s\t%d (elf header size)\n", "ehsize:", elf_header->e_ehsize);
	printf("%-16s\t%d (per program size)\n", "phentsize:", elf_header->e_phentsize);
	printf("%-16s\t%d (program header num)\n", "phnum:", elf_header->e_phnum);
	printf("%-16s\t%d (per section size)\n", "shentsize:", elf_header->e_shentsize);
	printf("%-16s\t%d (section num)\n", "shnum:", elf_header->e_shnum);
	printf("%-16s\t%d (section name string index)\n", "shstrndx:", elf_header->e_shstrndx);

	return 0;
}

char *parse_ph_type(uint32_t type)
{
	static char *desc_type;

	switch (type) {
	case PT_NULL:
		desc_type = "NULL";
		break;
	case PT_LOAD:
		desc_type = "LOAD";
		break;
	case PT_DYNAMIC:
		desc_type = "DYNAMIC";
		break;
	case PT_INTERP:
		desc_type = "INTERP";
		break;
	case PT_NOTE:
		desc_type = "NOTE";
		break;
	case PT_SHLIB:
		desc_type = "SHLIB";
		break;
	case PT_PHDR:
		desc_type = "PHDR";
		break;
	case PT_TLS:
		desc_type = "TLS";
		break;
	case PT_LOOS:
		desc_type = "LOOS";
		break;
	case PT_HIOS:
		desc_type = "HIOS";
		break;
	case PT_LOPROC:
		desc_type = "LOPROC";
		break;
	case PT_HIPROC:
		desc_type = "HIPROC";
		break;
	case PT_GNU_EH_FRAME:
		desc_type = "GNU_EH_FRAME";
		break;
	case PT_GNU_STACK:
		desc_type = "GNU_STACK";
		break;
	case PT_GNU_RELRO:
		desc_type = "GNU_RELRO";
		break;
	default:
		return NULL;
	}

	return desc_type;
}

static char *ph_flags[7] = {"X","W","WX","R","RX","RW","RWX"};

int display_program_headers(struct wdb_symbol *sym)
{
	int i;
	
	printf("%-16s%-16s  %-16s   %-16s\n\t\t%-16s  %-16s   %-8s%-8s\n\n",
		"type", "offset", "vaddr", "paddr",
		"filesz", "memsz", "flags", "align");

	for (i = 0; i < sym->elf_header->e_phnum; i++) {
		printf("%-16s0x%-16x0x%016x 0x%016x\n"
			"\t\t0x%-16x0x%-16x %-8s0x%-8x\n",
			parse_ph_type(sym->ph_header[i].p_type), 
			sym->ph_header[i].p_offset,
			sym->ph_header[i].p_vaddr, sym->ph_header[i].p_paddr,
			sym->ph_header[i].p_filesz, sym->ph_header[i].p_memsz,
			ph_flags[sym->ph_header[i].p_flags - 1], sym->ph_header[i].p_align);
	}

	return 0;
}

uint64_t get_libc_base(pid_t pid)
{
        FILE *fp;
        char file[64], buf[256];

        snprintf(file, sizeof(file) - 1, "/proc/%d/maps", pid);
        fp = fopen(file, "r");
        if (!fp) {
                perror("fopen");
                return 0;
        }

        while (fgets(buf, 256, fp) != NULL) {
                uint64_t addr1, addr2, tmp2, tmp3;
                char rwx[8], tmp1[16], lib[32];

                sscanf(buf, "%lx-%lx %s %lx %s %lx %s\n",
                        &addr1, &addr2, rwx, &tmp2, tmp1, &tmp3, lib);

                if (strstr(lib, "libc-") && rwx[2] == 'x') {
                        fclose(fp);
                        return addr1;
                }
        }

        fclose(fp);
        return 0;
}

char *string_name(void *mem, int offset)
{
        if (!mem || offset < 0)
                return NULL;

        return (char *)(mem + offset);
}

char *section_name(void *mem, int offset)
{
        return string_name(mem, offset);
}

char *symbol_name(void *mem, int offset)
{
        return string_name(mem, offset);
}

int read_elf_section(struct wdb_symbol *sym)
{
        int i;

        for (i = 0; i < sym->elf_header->e_shnum; i++) {
                if (sym->sh_header[i].sh_type == SHT_SYMTAB) {
                        sym->sym_table = &sym->sh_header[i];
                        continue;
                }
                if (sym->sh_header[i].sh_type == SHT_DYNSYM) {
                        sym->dsym_table = &sym->sh_header[i];
                        continue;
                }
                if (sym->sh_header[i].sh_type == SHT_DYNAMIC) {
                        sym->dyn_table = &sym->sh_header[i];
                        continue;
                }
                if (sym->sh_header[i].sh_type == SHT_REL) {
                        sym->rel_table[sym->rel_idx++] = &sym->sh_header[i];
                        continue;
		}
                if (sym->sh_header[i].sh_type == SHT_RELA) {
                        sym->rela_table[sym->rela_idx++] = &sym->sh_header[i];
                        continue;
		}
                if (!strcmp(section_name(sym->shstrtab_mem,
                                             sym->sh_header[i].sh_name),
                                             ".plt")) {
                        sym->plt_table = &sym->sh_header[i];
                        continue;
                }
                if (!strcmp(section_name(sym->shstrtab_mem,
                                             sym->sh_header[i].sh_name),
                                             ".strtab")) {
                        sym->strtab_mem =
                                (void *)(sym->base_addr + sym->sh_header[i].sh_offset);
                        continue;
                }
                if (!strcmp(section_name(sym->shstrtab_mem,
                                             sym->sh_header[i].sh_name),
                                             ".dynstr")) {
                        sym->dynstr_mem =
                                (void *)(sym->base_addr + sym->sh_header[i].sh_offset);
                        continue;
                }
        }

        return 0;
}

char *section_type(int type)
{
	static char *type_desc;

	switch (type) {
	case SHT_NULL:
		type_desc = "NULL";
		break;
	case SHT_PROGBITS:
		type_desc = "PROGBITS";
		break;
	case SHT_SYMTAB:
		type_desc = "SYMTAB";
		break;
	case SHT_STRTAB:
		type_desc = "STRTAB";
		break;
	case SHT_RELA:
		type_desc = "RELA";
		break;
	case SHT_HASH:
		type_desc = "HASH";
		break;
	case SHT_DYNAMIC:
		type_desc = "DYNAMIC";
		break;
	case SHT_NOTE:
		type_desc = "NOTE";
		break;
	case SHT_NOBITS:
		type_desc = "NOBITS";
		break;
	case SHT_REL:
		type_desc = "REL";
		break;
	case SHT_SHLIB:
		type_desc = "SHLIB";
		break;
	case SHT_DYNSYM:
		type_desc = "DYNSYM";
		break;
	case SHT_NUM:
		type_desc = "NUM";
		break;
	case SHT_LOPROC:
		type_desc = "LOPROC";
		break;
	case SHT_HIPROC:
		type_desc = "HIPROC";
		break;
	case SHT_LOUSER:
		type_desc = "LOUSER";
		break;
	case SHT_HIUSER:
		type_desc = "HIUSER";
		break;
	case SHT_GNU_HASH:
		type_desc = "GNU_HASH";
		break;
	case SHT_INIT_ARRAY:
		type_desc = "INIT_ARRAY";
		break;
	case SHT_FINI_ARRAY:
		type_desc = "FINI_ARRAY";
		break;
/*
	case SHT_VERSYM:
		type_desc = "VERSYM";
		break;
	case SHT_VERNEED:
		type_desc = "VERNEED";
		break;
*/
	default:
		type_desc = "UNKOWN";
		break;
	}

	return type_desc;
}

int display_section_headers(struct wdb_symbol *sym)
{
	int i;
	
	printf("%-8s%-16s   %-16s   %-16s   %-8s\n"
		"\t%-16s   %-16s   %-4s %-4s %-4s %-4s\n\n",
		"[NR]", "name", "type", "address", "offset", 
		"size", "entsize", "flags",  "link",  "info", "align");

	for (i = 0; i < sym->elf_header->e_shnum; i++) {
		printf("%-8d%-16s   %-16s   0x%016x 0x%08x\n"
			"\t0x%016x 0x%016x %-4d %-4d %-4d %-4d\n",
			i, section_name(sym->shstrtab_mem, sym->sh_header[i].sh_name), 
			section_type(sym->sh_header[i].sh_type),
			sym->sh_header[i].sh_addr, sym->sh_header[i].sh_offset,
			sym->sh_header[i].sh_size, sym->sh_header[i].sh_entsize,
			sym->sh_header[i].sh_flags, sym->sh_header[i].sh_link,
			sym->sh_header[i].sh_info, sym->sh_header[i].sh_addralign);
	}

	return 0;
}

char *symbol_type(int value)
{
	static char *type_desc;

	switch (value) {
	case STT_NOTYPE:
		type_desc = "NOTYPE";
		break;
	case STT_OBJECT:
		type_desc = "OBJECT";
		break;
	case STT_FUNC:
		type_desc = "FUNC";
		break;
	case STT_SECTION:
		type_desc = "SECTION";
		break;
	case STT_FILE:
		type_desc = "FILE";
		break;
	case STT_COMMON:
		type_desc = "COMMON";
		break;
	case STT_TLS:
		type_desc = "TLS";
		break;
	default:
		type_desc = "NULL";
	}

	return type_desc;
}

char *symbol_bind(int value)
{
	static char *bind_desc;

	switch (value) {
	case STB_LOCAL:
		bind_desc = "LOCAL";
		break;
	case STB_GLOBAL:
		bind_desc = "GLOBAL";
		break;
	case STB_WEAK:
		bind_desc = "WEAK";
		break;
	default:
		bind_desc = "Unknown";
	}

	return bind_desc;
}

char *symbol_vis(int value)
{
	static char *vis_desc;

	switch (value) {
	case STV_DEFAULT:
		vis_desc = "DEFAULT";
		break;
	case STV_INTERNAL:
		vis_desc = "INTERNAL";
		break;
	case STV_HIDDEN:
		vis_desc = "INTERNAL";
		break;
	case STV_PROTECTED:
		vis_desc = "PROTECTED";
		break;
	default:
		vis_desc = "NULL";
	}

	return vis_desc;
}

int64_t resolve_symbol_addr(struct wdb_symbol *sym, Elf64_Shdr *section, 
			void *mem, char *name)
{
        Elf64_Sym *sym_table;
        int i;

        sym_table = (Elf64_Sym *)(sym->base_addr + section->sh_offset);
        for (i = 0; i < section->sh_size/sizeof(Elf64_Sym); i++) {
                if (!strcmp(symbol_name(mem, sym_table[i].st_name), name))
                        return (int64_t)(sym_table[i].st_value);
        }

        return 0;
}

uint64_t fetch_symbol_addr(struct wdb_symbol *sym, char *name)
{
        uint64_t value;

        if (sym->strtab_mem) {
                value = resolve_symbol_addr(sym, sym->sym_table,
                                        sym->strtab_mem, name);
                if (value != 0)
                        return value;
        }

        if (sym->dynstr_mem) {
                value = resolve_symbol_addr(sym, sym->dsym_table,
                                        sym->dynstr_mem, name);
                if (value != 0)
                        return value;
        }

	return fetch_address_from_reloc(sym, name);
}

int32_t resolve_symbol_size(struct wdb_symbol *sym, Elf64_Shdr *section, 
			void *mem, uint64_t addr)
{
        Elf64_Sym *sym_table;
        int i;

        sym_table = (Elf64_Sym *)(sym->base_addr + section->sh_offset);
        for (i = 0; i < section->sh_size/sizeof(Elf64_Sym); i++) {
                if ((uint64_t)(sym->libc_addr + sym_table[i].st_value) == addr) {
                        return sym_table[i].st_size;
                }
        }

        return -1;
}

uint32_t fetch_symbol_size(struct wdb_symbol *sym, uint64_t addr)
{
        int32_t value;

        if (sym->strtab_mem) {
                value = resolve_symbol_size(sym, sym->sym_table,
                                            sym->strtab_mem, addr);
                if (value != -1)
                        return value;
        }

        if (sym->dynstr_mem) {
                value = resolve_symbol_size(sym, sym->dsym_table,
                                            sym->dynstr_mem, addr);
                if (value != -1)
                        return value;
        }

        return -1;
}

void __display_sym_table(struct wdb_symbol *sym, Elf64_Shdr *section, void *mem)
{
        Elf64_Sym *sym_table;
        int i;

	printf("%-4s %-16s   %-4s %-8s %-10s %-10s %-8s %-32s\n",
		"num", "value", "size", "type", "bind", "vis", "ndx", "name");

        sym_table = (Elf64_Sym *)(sym->base_addr + section->sh_offset);
        for (i = 0; i < section->sh_size/sizeof(Elf64_Sym); i++) {
                printf("%-4d 0x%016x %-4d %-8s %-10s %-10s %-8d %-32s\n",
                        i, sym_table[i].st_value,
                        sym_table[i].st_size,
                        symbol_type(ELF64_ST_TYPE(sym_table[i].st_info)),
                        symbol_bind(ELF64_ST_BIND(sym_table[i].st_info)),
                        symbol_vis(ELF64_ST_VISIBILITY(sym_table[i].st_other)),
                        sym_table[i].st_shndx,
                        symbol_name(mem, sym_table[i].st_name));
        }
}

void display_sym_table(struct wdb_symbol *sym)
{
        if (sym->dynstr_mem)
                __display_sym_table(sym, sym->sym_table, sym->strtab_mem);
}

void display_dsym_table(struct wdb_symbol *sym)
{
        if (sym->dynstr_mem)
                __display_sym_table(sym, sym->dsym_table, sym->dynstr_mem);
}

char *rela_type(int value)
{
        static char *type_desc;

        switch (value) {
        case R_X86_64_NONE:
                type_desc = "R_X86_64_NONE";
                break;
        case R_X86_64_64:
                type_desc = "R_X86_64_64";
                break;
        case R_X86_64_PC32:
                type_desc = "R_X86_64_PC32";
                break;
        case R_X86_64_GOT32:
                type_desc = "R_X86_64_GOT32";
                break;
        case R_X86_64_PLT32:
                type_desc = "R_X86_64_PLT32";
                break;
        case R_X86_64_COPY:
                type_desc = "R_X86_64_COPY";
                break;
        case R_X86_64_GLOB_DAT:
                type_desc = "R_X86_64_GLOB_DAT";
                break;
        case R_X86_64_JUMP_SLOT:
                type_desc = "R_X86_64_JUMP_SLOT";
                break;
        case R_X86_64_RELATIVE:
                type_desc = "R_X86_64_RELATIVE";
                break;
        case R_X86_64_GOTPCREL:
                type_desc = "R_X86_64_GOTPCREL";
                break;
        case R_X86_64_32:
                type_desc = "R_X86_64_32";
                break;
        case R_X86_64_32S:
                type_desc = "R_X86_64_32S";
                break;
        case R_X86_64_16:
                type_desc = "R_X86_64_16";
                break;
        case R_X86_64_PC16:
                type_desc = "R_X86_64_PC16";
                break;
        case R_X86_64_8:
                type_desc = "R_X86_64_8";
                break;
        case R_X86_64_PC8:
                type_desc = "R_X86_64_PC8";
                break;
        case R_X86_64_DTPMOD64:
                type_desc = "R_X86_64_DTPMOD64";
                break;
        case R_X86_64_DTPOFF64:
                type_desc = "R_X86_64_DTPOFF64";
                break;
        case R_X86_64_TLSGD:
                type_desc = "R_X86_64_TLSGD";
                break;
        case R_X86_64_TLSLD:
                type_desc = "R_X86_64_TLSLD";
                break;
        case R_X86_64_DTPOFF32:
                type_desc = "R_X86_64_DTPOFF32";
                break;
        case R_X86_64_GOTTPOFF:
                type_desc = "R_X86_64_GOTTPOFF";
                break;
        case R_X86_64_TPOFF32:
                type_desc = "R_X86_64_TPOFF32";
                break;
        case R_X86_64_PC64:
                type_desc = "R_X86_64_PC64";
                break;
        case R_X86_64_GOTOFF64:
                type_desc = "R_X86_64_GOTOFF64";
                break;
        case R_X86_64_GOTPC32:
                type_desc = "R_X86_64_GOTPC32";
                break;
        case R_X86_64_GOT64:
                type_desc = "R_X86_64_GOT64";
                break;
        case R_X86_64_GOTPCREL64:
                type_desc = "R_X86_64_GOTPCREL64";
                break;
        case R_X86_64_GOTPC64:
                type_desc = "R_X86_64_GOTPC64";
                break;
        case R_X86_64_GOTPLT64:
                type_desc = "R_X86_64_GOTPLT64";
                break;
        case R_X86_64_PLTOFF64:
                type_desc = "R_X86_64_PLTOFF64";
                break;
        case R_X86_64_SIZE32:
                type_desc = "R_X86_64_SIZE32";
                break;
        case R_X86_64_SIZE64:
                type_desc = "R_X86_64_SIZE64";
                break;
        case R_X86_64_GOTPC32_TLSDESC:
                type_desc = "R_X86_64_GOTPC32_TLSDESC";
                break;
        case R_X86_64_TLSDESC_CALL:
                type_desc = "R_X86_64_TLSDESC_CALL";
                break;
        case R_X86_64_TLSDESC:
                type_desc = "R_X86_64_TLSDESC";
                break;
        case R_X86_64_IRELATIVE:
                type_desc = "R_X86_64_IRELATIVE";
                break;
        case R_X86_64_RELATIVE64:
                type_desc = "R_X86_64_RELATIVE64";
                break;
        default:
                type_desc = "Unknown";
        }

        return type_desc;
}

Elf64_Sym *get_rel_sym(struct wdb_symbol *sym, int idx)
{
	Elf64_Sym *sym_table;
	
        sym_table = (Elf64_Sym *)(sym->base_addr + sym->dsym_table->sh_offset);
	return &sym_table[idx];
}

void __display_rel_table(struct wdb_symbol *sym, Elf64_Shdr *section, void *mem)
{
        Elf64_Rel *rel_table;
        int i;

        printf("%-16s   %-16s   %-20s%-16s    %-32s\n",
                "offset", "info", "type","sym.value", "sym.name");

        rel_table = (Elf64_Rel *)(sym->base_addr + section->sh_offset);
        for (i = 0; i < section->sh_size/sizeof(Elf64_Rel); i++) {
                Elf64_Sym *symbol;

                symbol = get_rel_sym(sym, ELF64_R_SYM(rel_table[i].r_info));
                if (!symbol)
                        continue;

                printf("0x%016x 0x%016x %-20s0x%016x  %s\n",
                        rel_table[i].r_offset,
                        rel_table[i].r_info,
                        rela_type(ELF64_R_TYPE(rel_table[i].r_info)),
                        symbol->st_value, symbol_name(mem, symbol->st_name));
        }
}

void display_rel_table(struct wdb_symbol *sym)
{
	int i;

	for (i = 0; i < sym->rel_idx; i++) {
		__display_rel_table(sym, sym->rel_table[i], sym->dynstr_mem);
		printf("\n");
	}
}

void __display_rela_table(struct wdb_symbol *sym, Elf64_Shdr *section, void *mem)
{
        Elf64_Rela *rela_table;
        int i;

        printf("%-16s   %-16s   %-20s%-16s    %-32s\n",
                "offset", "info", "type","sym.value", "sym.name + addend");

        rela_table = (Elf64_Rela *)(sym->base_addr + section->sh_offset);
        for (i = 0; i < section->sh_size/sizeof(Elf64_Rela); i++) {
                Elf64_Sym *symbol;

                symbol = get_rel_sym(sym, ELF64_R_SYM(rela_table[i].r_info));
                if (!symbol)
                        continue;

                printf("0x%016x 0x%016x %-20s0x%016x  %s + %d\n",
                        rela_table[i].r_offset,
                        rela_table[i].r_info,
                        rela_type(ELF64_R_TYPE(rela_table[i].r_info)),
                        symbol->st_value, symbol_name(mem, symbol->st_name),
                        rela_table[i].r_addend);
        }
}

void display_rela_table(struct wdb_symbol *sym)
{
        int i;

        for (i = 0; i < sym->rela_idx; i++) {
                __display_rela_table(sym, sym->rela_table[i], sym->dynstr_mem);
		printf("\n");
        }
}

uint64_t __fetch_address_from_rel(struct wdb_symbol *sym, 
				Elf64_Shdr *section, 
				void *mem, 
				char *name)
{
        Elf64_Rel *rel_table;
        int i;

        rel_table = (Elf64_Rel *)(sym->base_addr + section->sh_offset);
        for (i = 0; i < section->sh_size/sizeof(Elf64_Rel); i++) {
                Elf64_Sym *symbol;

                symbol = get_rel_sym(sym, ELF64_R_SYM(rel_table[i].r_info));
                if (!symbol)
                        continue;

		if (!strcmp(symbol_name(mem, symbol->st_name), name))
			return sym->plt_table->sh_addr + (i + 1) * 0x10;
        }

	return 0;
}

uint64_t fetch_address_from_rel(struct wdb_symbol *sym, char *name)
{
	uint64_t addr;
        int i;

        for (i = 0; i < sym->rel_idx; i++) {
                addr = __fetch_address_from_rel(sym, sym->rel_table[i], 
						sym->dynstr_mem, name);
		if (addr != 0)
			return addr;
        }

	return 0;
}

uint64_t __fetch_address_from_rela(struct wdb_symbol *sym, 
				Elf64_Shdr *section, 
				void *mem, 
				char *name)
{
        Elf64_Rela *rela_table;
        int i;

        rela_table = (Elf64_Rela *)(sym->base_addr + section->sh_offset);
        for (i = 0; i < section->sh_size/sizeof(Elf64_Rela); i++) {
                Elf64_Sym *symbol;

                symbol = get_rel_sym(sym, ELF64_R_SYM(rela_table[i].r_info));
                if (!symbol)
                        continue;

		if (!strcmp(symbol_name(mem, symbol->st_name), name))
			return sym->plt_table->sh_addr + (i + 1) * 0x10;
        }

	return 0;
}

uint64_t fetch_address_from_rela(struct wdb_symbol *sym, char *name)
{
	uint64_t addr;
        int i;

        for (i = 0; i < sym->rela_idx; i++) {
                addr = __fetch_address_from_rela(sym, sym->rela_table[i], 
						sym->dynstr_mem, name);
		if (addr != 0)
			return addr;
        }

	return 0;
}

uint64_t fetch_address_from_reloc(struct wdb_symbol *sym, char *name)
{
	uint64_t addr;
	
	addr = fetch_address_from_rel(sym, name);
	if (addr != 0)
		return addr;

	return fetch_address_from_rela(sym, name);
}

char *dyn_needed_string(void *mem, uint64_t idx)
{
	return symbol_name(mem, idx);
}

int read_dyn_tag(Elf64_Dyn *dyn, void *mem, 
		uint64_t *value, char *type, 
		char *string)
{
	int rc = -1;

	switch (dyn->d_tag) {
	case DT_NULL:
		break;
	case DT_NEEDED:
		strcpy(type, "NEEDED");
		strcpy(string, dyn_needed_string(mem, dyn->d_un.d_val));
		rc = 1;
		break;
	case DT_PLTRELSZ:
		strcpy(type, "PLTRELSZ");
		*value = dyn->d_un.d_val;
		rc = 2;
		break;
	case DT_PLTGOT:
		strcpy(type, "PLTGOT");
		*value = dyn->d_un.d_val;
		rc = 2;
		break;
	case DT_HASH:
		strcpy(type, "HASH");
		*value = dyn->d_un.d_val;
		rc = 2;
		break;
	case DT_STRTAB:
		strcpy(type, "STRTAB");
		*value = dyn->d_un.d_val;
		rc = 2;
		break;
	case DT_SYMTAB:
		strcpy(type, "SYMTAB");
		*value = dyn->d_un.d_val;
		rc = 2;
		break;
	case DT_RELA:
		strcpy(type, "RELA");
		*value = dyn->d_un.d_val;
		rc = 2;
		break;
	case DT_RELASZ:
		strcpy(type, "RELASZ");
		*value = dyn->d_un.d_val;
		rc = 2;
		break;
	case DT_RELAENT:
		strcpy(type, "RELAENT");
		*value = dyn->d_un.d_val;
		rc = 2;
		break;
	case DT_STRSZ:
		strcpy(type, "STRSZ");
		*value = dyn->d_un.d_val;
		rc = 2;
		break;
	case DT_SYMENT:
		strcpy(type, "SYMENT");
		*value = dyn->d_un.d_val;
		rc = 2;
		break;
	case DT_INIT:
		strcpy(type, "INIT");
		*value = dyn->d_un.d_val;
		rc = 2;
		break;
	case DT_FINI:
		strcpy(type, "FINI");
		*value = dyn->d_un.d_val;
		rc = 2;
		break;
	case DT_SONAME:
		strcpy(type, "SONAME");
		strcpy(string, dyn_needed_string(mem, dyn->d_un.d_val));
		rc = 1;
		break;
	case DT_RPATH:
		strcpy(type, "RPATH");
		strcpy(string, dyn_needed_string(mem, dyn->d_un.d_val));
		rc = 1;
		break;
	case DT_SYMBOLIC:
		strcpy(type, "SYMBOLIC");
		*value = dyn->d_un.d_val;
		rc = 2;
		break;
	case DT_REL:
		strcpy(type, "REL");
		*value = dyn->d_un.d_val;
		rc = 2;
		break;
	case DT_RELSZ:
		strcpy(type, "RELSZ");
		*value = dyn->d_un.d_val;
		rc = 2;
		break;
	case DT_RELENT:
		strcpy(type, "RELENT");
		*value = dyn->d_un.d_val;
		rc = 2;
		break;
	case DT_PLTREL:
		strcpy(type, "PLTREL");
		//printf("!!%d\n", dyn->d_un.d_val);
		string[0] = '\0';
		rc = 1;
		break;
	case DT_DEBUG:
		strcpy(type, "DEBUG");
		*value = 0;
		rc = 2;
		break;
	case DT_TEXTREL:
		strcpy(type, "TEXTREL");
		*value = dyn->d_un.d_val;
		rc = 2;
		break;
	case DT_JMPREL:
		strcpy(type, "JMPREL");
		*value = dyn->d_un.d_val;
		rc = 2;
		break;
	case DT_BIND_NOW:
		strcpy(type, "BIND_NOW");
		*value = dyn->d_un.d_val;
		rc = 2;
		break;
	case DT_RUNPATH:
		strcpy(type, "BIND_NOW");
		strcpy(string, dyn_needed_string(mem, dyn->d_un.d_val));
		rc = 1;
		break;
	case DT_LOPROC:
		strcpy(type, "LOPROC");
		*value = dyn->d_un.d_val;
		rc = 2;
		break;
	case DT_HIPROC:
		strcpy(type, "HIPROC");
		*value = dyn->d_un.d_val;
		rc = 2;
		break;
	case DT_FLAGS_1:
		strcpy(type, "FLAGS_1");
		*value = dyn->d_un.d_val;
		rc = 2;
		break;
	case DT_VERDEF:
		strcpy(type, "VERDEF");
		*value = dyn->d_un.d_val;
		rc = 2;
		break;
	case DT_VERDEFNUM:
		strcpy(type, "VERDEFNUM");
		*value = dyn->d_un.d_val;
		rc = 2;
		break;
	case DT_VERNEED:
		strcpy(type, "VERNEED");
		*value = dyn->d_un.d_val;
		rc = 2;
		break;
	case DT_VERNEEDNUM:
		strcpy(type, "VERNEEDNUM");
		*value = dyn->d_un.d_val;
		rc = 2;
		break;
	case DT_VERSYM:
		strcpy(type, "VERSYM");
		*value = dyn->d_un.d_val;
		rc = 2;
		break;
	case DT_RELACOUNT:
		strcpy(type, "RELACOUNT");
		*value = dyn->d_un.d_val;
		rc = 2;
		break;
	case DT_RELCOUNT:
		strcpy(type, "RELCOUNT");
		*value = dyn->d_un.d_val;
		rc = 2;
		break;
	case DT_INIT_ARRAY:
		strcpy(type, "INIT_ARRAY");
		*value = dyn->d_un.d_val;
		rc = 2;
		break;
	case DT_FINI_ARRAY:
		strcpy(type, "FINI_ARRAY");
		*value = dyn->d_un.d_val;
		rc = 2;
		break;
	case DT_INIT_ARRAYSZ:
		strcpy(type, "INIT_ARRAYSZ");
		*value = dyn->d_un.d_val;
		rc = 2;
		break;
	case DT_FINI_ARRAYSZ:
		strcpy(type, "FINI_ARRAYSZ");
		*value = dyn->d_un.d_val;
		rc = 2;
		break;
	case DT_ENCODING - 1:
		strcpy(type, "ENCODING");
		*value = dyn->d_un.d_val;
		rc = 2;
		break;
	case DT_PREINIT_ARRAY:
		strcpy(type, "PREINIT_ARRAY");
		*value = dyn->d_un.d_val;
		rc = 2;
		break;
	case DT_PREINIT_ARRAYSZ:
		strcpy(type, "PREINIT_ARRAYSZ");
		*value = dyn->d_un.d_val;
		rc = 2;
		break;
	case DT_NUM:
		strcpy(type, "NUM");
		*value = dyn->d_un.d_val;
		rc = 2;
		break;
	default:
		return rc;
	}

	return rc;
}

void display_dynamic_table(struct wdb_symbol *sym)
{
	Elf64_Dyn *dyn_table;
        uint64_t dyn_num;
        int i = 0, rc = -1;

	dyn_table = (Elf64_Dyn *)(sym->base_addr + sym->dyn_table->sh_offset);
        dyn_num = sym->dyn_table->sh_size / sizeof(Elf64_Dyn);

        printf("section %s has %d nums.\n\n",
                section_name(sym->shstrtab_mem, sym->dyn_table->sh_name), dyn_num);
        printf("%-16s   %-16s %-16s\n", "tag", "type", "name/value");

        for (i = 0; i < dyn_num; i++) {
		uint64_t value = 0;
		char type[64], string[64];

		rc = read_dyn_tag(&dyn_table[i], sym->dynstr_mem, &value, type, string);
		if (rc == 1)
                	printf("0x%016x %-16s %-16s\n", dyn_table[i].d_tag, type, string);
		else if (rc == 2)
                	printf("0x%016x %-16s 0x%016x\n", dyn_table[i].d_tag, type, value);
		else
			continue;
        }
}

int resolve_need_symbols(struct wdb_symbol *sym)
{

	Elf64_Dyn *dyn_table;
        uint64_t dyn_num;
        int i = 0, rc = -1;

	dyn_table = (Elf64_Dyn *)(sym->base_addr + sym->dyn_table->sh_offset);
        dyn_num = sym->dyn_table->sh_size / sizeof(Elf64_Dyn);

        for (i = 0; i < dyn_num; i++) {
		if (dyn_table[i].d_tag == DT_NEEDED) {
			char file[128];

			snprintf(file, 
				sizeof(file) - 1, 
				"%s/%s", 
				DEFAULT_LIBC_PATH, 
				dyn_needed_string(sym->dynstr_mem, dyn_table[i].d_un.d_val));

        		wdb_syms[wdb_sym_idx].elf_path = strdup(file);
        		if (load_elf_symbols(&wdb_syms[wdb_sym_idx]) == -1)
                		return -1;

        		printf("load symbols from %s ok.\n", file);
			wdb_sym_idx++;
			rc = 1;
		}
        }

	return rc;
}
