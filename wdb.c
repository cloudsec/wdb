#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <elf.h>
#include <errno.h>

#include "wdb.h"
#include "console.h"
#include "libelf.h"

char *target_binary = NULL;
pid_t c_pid;
int ptrace_state = 0;
int step_state = 0;

int wdb_get_regs(struct user_regs_struct *regs)
{
        if (ptrace(PTRACE_GETREGS, c_pid, NULL, regs) == -1) {
                perror("ptrace");
                return -1;
        }

	return 0;
}

void wdb_show_regs(void)
{
	struct user_regs_struct regs;

	if (wdb_get_regs(&regs) == -1)
		return ;

	printf("rax 0x%lx\n"
                "rbx 0x%lx\n"
                "rcx 0x%lx\n"
                "rdx 0x%lx\n"
                "rsi 0x%lx\n"
                "rdi 0x%lx\n"
                "rbp 0x%lx\n"
                "rsp 0x%lx\n"
                "r8 0x%lx\n"
                "r9 0x%lx\n"
                "r10 0x%lx\n"
                "r11 0x%lx\n"
                "r12 0x%lx\n"
                "r13 0x%lx\n"
                "r14 0x%lx\n"
                "r15 0x%lx\n"
                "rip 0x%lx\n"
                "eflags 0x%lx\n"
                "cs 0x%lx\n"
                "ss 0x%lx\n"
                "ds 0x%lx\n"
                "es 0x%lx\n"
                "fs 0x%lx\n"
                "gs 0x%lx\n",
		regs.rax, regs.rbx, regs.rcx,
		regs.rdx, regs.rsi, regs.rdi,
		regs.rbp, regs.rsp, regs.r8,
		regs.r9, regs.r10, regs.r11, 
		regs.r12, regs.r13, regs.r14, 
		regs.r15, regs.rip, regs.eflags, 
		regs.cs, regs.ss, regs.ds, 
		regs.es, regs.fs, regs.gs);
}

uint64_t get_reg_value(char *reg_name)
{
	struct user_regs_struct regs;

	if (wdb_get_regs(&regs) == -1)
		return -1;

	if (!strcmp(reg_name, "rax"))
		return regs.rax;
	else if (!strcmp(reg_name, "rbx"))
		return regs.rbx;
	else if (!strcmp(reg_name, "rcx"))
		return regs.rcx;
	else if (!strcmp(reg_name, "rdx"))
		return regs.rdx;
	else if (!strcmp(reg_name, "rsi"))
		return regs.rsi;
	else if (!strcmp(reg_name, "rdi"))
		return regs.rdi;
	else if (!strcmp(reg_name, "rbp"))
		return regs.rbp;
	else if (!strcmp(reg_name, "rsp"))
		return regs.rsp;
	else if (!strcmp(reg_name, "r8"))
		return regs.r8;
	else if (!strcmp(reg_name, "r9"))
		return regs.r9;
	else if (!strcmp(reg_name, "r10"))
		return regs.r10;
	else if (!strcmp(reg_name, "r11"))
		return regs.r11;
	else if (!strcmp(reg_name, "r12"))
		return regs.r12;
	else if (!strcmp(reg_name, "r13"))
		return regs.r13;
	else if (!strcmp(reg_name, "r14"))
		return regs.r14;
	else if (!strcmp(reg_name, "r15"))
		return regs.r15;
	else if (!strcmp(reg_name, "rip"))
		return regs.rip;
	else if (!strcmp(reg_name, "eflags"))
		return regs.eflags;
	else if (!strcmp(reg_name, "cs"))
		return regs.cs;
	else if (!strcmp(reg_name, "ds"))
		return regs.ds;
	else if (!strcmp(reg_name, "es"))
		return regs.es;
	else if (!strcmp(reg_name, "fs"))
		return regs.fs;
	else if (!strcmp(reg_name, "gs"))
		return regs.gs;
	else if (!strcmp(reg_name, "ss"))
		return regs.ss;
	else
		return -1;
}

void print_bps(void)
{
	int i;

	printf("break points:\n");
	for (i = 0; i < MAX_BREAKPOINT_NUM; i++) {
		if (bp_bitmap[i] == 1) {
			printf("<%d> 0x%lx\t%s\n", 
				i, wdb_bp[i].bp_addr,
				 wdb_bp[i].bp_symbol ? wdb_bp[i].bp_symbol : "NULL");
		}
	}
}

int alloc_bp(void)
{
	int i;

	for (i = 0; i < MAX_BREAKPOINT_NUM; i++) {
		if (!bp_bitmap[i]) {
			bp_bitmap[i] = 1;
			return i;
		}
	}

	return -1;
}

void free_bp(int n)
{
	if (n < 0 || n >= MAX_BREAKPOINT_NUM)
		return ;

	bp_bitmap[n] = 0;
}

int search_bp_symbol(char *symbol)
{
	int i;

	for (i = 0; i < MAX_BREAKPOINT_NUM; i++) {
		if (bp_bitmap[i] == 1 && !strcmp(wdb_bp[i].bp_symbol, symbol))
			return i;
	}

	return -1;
}

int search_bp_address(uint64_t addr)
{
	int i;

	for (i = 0; i < MAX_BREAKPOINT_NUM; i++) {
		if (bp_bitmap[i] == 1 && wdb_bp[i].bp_addr == addr)
				return i;
	}

	return -1;
}

int delete_bp_array(int idx)
{
	if (idx < 0 || idx >= MAX_BREAKPOINT_NUM)
		return -1;

	bp_bitmap[idx] = 0;
	memset(&wdb_bp[idx], 0, sizeof(struct wdb_breakpoint));

	return 0;
}

void wdb_breakpoints_init(void)
{
	memset(&wdb_bp, 0, sizeof(wdb_bp));
	memset(&bp_bitmap, 0, sizeof(bp_bitmap));
}

int ptrace_read_word(pid_t pid, uint64_t addr, long *value)
{
	long n;

	/*
         * the return value by ptrace() may be -1, so check
         * the errno value to determine whether or not an 
         * error occurred.
         */
	errno = 0;
	n = ptrace(PTRACE_PEEKTEXT, c_pid, addr, NULL);
	if (n == -1) {
		if (errno == EBUSY || errno == EFAULT || 
			errno == EINVAL || errno == EIO || 
			errno == ESRCH || errno == EPERM) {
			perror("ptrace");
			return -1;
		}
	}

	*value = n;
	return 0;
}

int ptrace_read_memory(pid_t pid, uint64_t addr, void *buf, int size)
{
        long n, sum = 0;

        while (sum < size) {
		if (ptrace_read_word(pid, addr + sum, &n) == -1)
			return -1;

                printf("0x%x %4d -> %4d 0x%016lx\n", addr + sum, size, sum, n);
                *(long *)(buf + sum) = n;
                sum += sizeof(long);
        }

        return 0;
}

int wdb_set_breakpoint(struct wdb_breakpoint *bp)
{
	long tmp;

	if (ptrace_read_word(c_pid, bp->bp_addr, &bp->bp_orig_data) == -1)
		return -1;
	printf("bp: 0x%016x\t0x%x\n", bp->bp_addr, bp->bp_orig_data);

	tmp = (bp->bp_orig_data & ~0xff) | 0xcc;
	if (ptrace(PTRACE_POKETEXT, c_pid, bp->bp_addr, tmp) == -1) {
		perror("ptrace");
		return -1;
	}

	if (ptrace_read_word(c_pid, bp->bp_addr, &tmp) == -1)
		return -1;
	printf("bp: 0x%016x\t0x%x\n", bp->bp_addr, tmp);

	return 0;
}

int wdb_set_breakpoints(void)
{
	int i;

	for (i = 0; i < MAX_BREAKPOINT_NUM; i++) {
		if (bp_bitmap[i] == 1) {
			if (wdb_set_breakpoint(&wdb_bp[i]) == -1)
				return -1;
		}
	}

	return 0;
}

int __wdb_delete_breakpoint(struct wdb_breakpoint *bp)
{
        long tmp;

	if (ptrace_read_word(c_pid, bp->bp_addr, &tmp) == -1)
		return -1;
	printf("bp: 0x%016x\t0x%x\n", bp->bp_addr, tmp);

        if (ptrace(PTRACE_POKETEXT, c_pid, bp->bp_addr, bp->bp_orig_data) == -1) {
                perror("ptrace");
                return -1;
        }

	if (ptrace_read_word(c_pid, bp->bp_addr, &tmp) == -1)
		return -1;
	printf("bp: 0x%016x\t0x%x\n", bp->bp_addr, tmp);

	return 0;
}

void show_regs(struct user_regs_struct *regs)
{
	printf("rip: 0x%016x\n", regs->rip);
}

int wdb_fixup_rip(void)
{
        struct user_regs_struct regs;
        int n;

        if (ptrace(PTRACE_GETREGS, c_pid, NULL, &regs) == -1) {
                perror("ptrace");
                return -1;
        }

        show_regs(&regs);
	regs.rip = regs.rip - 1;

        if (ptrace(PTRACE_SETREGS, c_pid, NULL, &regs) == -1) {
                perror("ptrace");
                return -1;
        }

        if (ptrace(PTRACE_GETREGS, c_pid, NULL, &regs) == -1) {
                perror("ptrace");
                return -1;
        }
        show_regs(&regs);

	return 0;
}

/*
 * delete a breakpoint.
 *
 * flag 0 - restore the orig opcode.
 * flag 1 - restore the orig opcode and delete it from the 
 * 	    global breakpoints array.
 */
int wdb_delete_breakpoint(int n, int flag)
{
	if (n == -1)
		return -1;

	if (__wdb_delete_breakpoint(&wdb_bp[n]) == -1)
		return -1;

	if (flag == 0) {
		if (wdb_fixup_rip() == -1)
			return -1;
	}

	if (flag == 1) {
		printf("delete breakpoint 0x%x\n", wdb_bp[n].bp_addr);
		if (delete_bp_array(n) == -1)
			return -1;
	}

	return 0;
}

int wdb_continue_program(void)
{
	if (ptrace(PTRACE_CONT, c_pid, NULL, NULL) == -1) {
		perror("ptrace");
		return -1;
	}
	return 0;
}

int wdb_got_control(int flag)
{
	int status;

	if (waitpid(c_pid, &status, flag) == -1) {
		perror("waitpid");
		return -1;
	}

        if (WIFEXITED(status)) {
                printf("child process has been exitd, stauts: %d.\n", 
			WEXITSTATUS(status));
		ptrace_state = 0;
                return 1;
        }
        else if (WIFSIGNALED(status)) {
                printf("child process was terminted by signal %d\n", 
			WTERMSIG(status));
		ptrace_state = 0;
                return 2;
        }
        else if (WCOREDUMP(status)) {
                printf("child process was coredumped.\n");
		ptrace_state = 0;
                return 3;
        }
        else if (WIFSTOPPED(status)) {
                if (WSTOPSIG(status) == SIGTRAP) {
                        return 0;
                }
		printf("child got a signal: %d\n", WSTOPSIG(status));
		ptrace_state = 0;
		return 4;
        }
	else if (WIFCONTINUED(status)) {
		printf("child process contined ...\n");
		return 5;
	}
        else {
                printf("child process got exception.\n");
		ptrace_state = 0;
                return -1;
        }

        return -1;
}

/* check which breakpoint we have got. */
int wdb_check_breakpoints(void)
{
	struct user_regs_struct regs;
	int n;

	if (ptrace(PTRACE_GETREGS, c_pid, NULL, &regs) == -1) {
		perror("ptrace");
		return -1;
	}

	n = search_bp_address(regs.rip - 1);
	if (n == -1) {
		//printf("can't find break points.\n");
		return -1;
	}
	printf("hint bp: 0x%x\n", regs.rip - 1);

	return n;
}

int __wdb_restore_breakpoint(int bp)
{
        /* restore the orig opcode. */
        if (wdb_delete_breakpoint(bp, 0) == -1)
                return -1;

        /* set a single step command. */
        if (ptrace(PTRACE_SINGLESTEP, c_pid, NULL, NULL) == -1) {
                perror("ptrace");
                return -1;
        }

        /* got the single step. */
        if (wdb_got_control(0) == -1)
                return -1;

        /* restore the prev breakpoint. */
        if (wdb_set_breakpoint(&wdb_bp[bp]) == -1)
                return -1;

        return 0;
}

int wdb_restore_breakpoint(void)
{
	int bp;

	if (step_state == 1) {
		step_state = 0;
		return 0;
	}
		
	bp = wdb_check_breakpoints();
	if (bp == -1)
		return -1;

	if (__wdb_restore_breakpoint(bp) == -1)
		return -1;

        return 0;
}

int wdb_wait_breakpoints(void)
{
	struct user_regs_struct regs;
	int n;

	/* enter the breakpoint. */
	n = wdb_got_control(0);
	if (n == 0) {
		if (ptrace(PTRACE_GETREGS, c_pid, NULL, &regs) == -1) {
			perror("ptrace");
			return -1;
		}
		//printf("next rip => 0x%lx\n", regs.rip);

		return 0;
	}

	/* otherwise, we need to exit the debugger console. */
	return -1;
}

int do_step_instruction(void)
{
        if (ptrace(PTRACE_SINGLESTEP, c_pid, NULL, NULL) == -1) {
                perror("ptrace");
                return -1;
        }

	if (wdb_wait_breakpoints() == -1)
		return -1;

	/* XXX do not forget to set step state. */
	step_state = 1;
	return 0;
}

int wdb_step_instruction(void)
{
	struct user_regs_struct regs;
	int bp;

	/* whether from a breakpoint, or a single step. */
	bp = wdb_check_breakpoints();
	if (bp >= 0) {
		if (wdb_restore_breakpoint() == -1)
			return -1;
	}

	return do_step_instruction();
}

uint64_t check_func_address(struct user_regs_struct *reg)
{
	uint64_t addr;
	long offset;

	if (ptrace_read_word(c_pid, reg->rip + 1, &offset) == -1)
		return -1;

	/* call(0xe8) has 5 in instructions. */
	addr = reg->rip + (int)(offset & 0xffffffff) + 5;
	printf("function offset 0x%x, addr is 0x%lx\n", offset, addr);
	
	/* next step is a function. */
	return 0;
}

int wdb_ni_instruction(void)
{
	uint64_t next_rip = 0;
	int bp, flag = 0;

	/* whether from a breakpoint, or a single step. */
	bp = wdb_check_breakpoints();
	if (bp >= 0) {
		if (wdb_restore_breakpoint() == -1)
			return -1;
	}

	for (;;) {
		struct user_regs_struct regs;
		long tmp = 0;

		if (ptrace(PTRACE_GETREGS, c_pid, NULL, &regs) == -1) {
			perror("ptrace");
			return -1;
		}

		if (regs.rip == next_rip) {
			printf("function call chain execute done.\n");
			break;
		}

		if (ptrace_read_word(c_pid, regs.rip, &tmp) == -1)
			return -1;
		
		if ((unsigned char)(tmp & 0xff) == 0xc3) {
			printf("function execute will done.\n");
		}

		if ((unsigned char)(tmp & 0xff) == 0xcc) {
			printf("#enter breakpoint: 0x%lx\n", regs.rip);
			break;
		}

		/* found the call instrcution. */
		if ((unsigned char)(tmp & 0xff) == 0xe8) {
			check_func_address(&regs);
			if (flag == 0) {
				next_rip = regs.rip + 5;
				printf("next rip is 0x%lx\n", next_rip);
				flag = 1;
			}
		}

		if (do_step_instruction() == -1)
			return -1;
	}

	return do_step_instruction();
}

int wdb_attach_program(void)
{
	int status;

	c_pid = fork();
	if (c_pid < 0) {
		perror("fork");
		return -1;
	}

	if (c_pid == 0) {
		if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
			perror("ptrace");
			exit(-1);
		}

		wdb_run_binary();
	}

	if (wdb_got_control(0) == -1) {
		printf("attach to child process %d failed.\n", c_pid);
		return -1;
	}

	ptrace_state = 1;
	printf("attach to child process %d ok.\n", c_pid);
	return 0;
}

int wdb_detach_program(void)
{
	if (ptrace(PTRACE_DETACH, c_pid, NULL, NULL) == -1) {
		if (errno == ESRCH)
			return 0;
		perror("ptrace");
		return -1;
	}

	printf("detach from child process %d ok.\n", c_pid);
	ptrace_state = 0;
	return 0;
}

int wdb_fixup_libc_address(pid_t pid)
{
	uint64_t addr;
	int i;

	addr = get_libc_base(pid);
	if (!addr) {
		printf("get libc address failed.\n");
		return -1;
	}
	printf("libc address: %p\n", addr);

	for (i = 0; i < wdb_sym_idx; i++) {
		wdb_syms[i].libc_addr = (void *)addr;
	}

	return 0;
}

uint64_t wdb_symbol_addr(char *sym_name)
{
	uint64_t addr;
	int i;

	for (i = 0; i < wdb_sym_idx; i++) {
		addr = fetch_symbol_addr(&wdb_syms[i], sym_name);
		if (addr != 0)
			return addr;
	}

	return 0;
}

int32_t wdb_symbol_size(uint64_t sym_addr)
{
	uint32_t size;
	int i;

	for (i = 0; i < wdb_sym_idx; i++) {
		size = fetch_symbol_size(&wdb_syms[i], sym_addr);
		if (size != 0)
			return size;
	}

	return 0;
}

int load_elf_symbols(struct wdb_symbol *sym)
{
	if (mmap_elf_binary(sym) == -1)
		return -1;

	if (read_elf_section(sym) == -1)
		goto out;

	return 0;
out:
	unmap_elf_binary(sym);
	return -1;
}

int wdb_symbol_init(char *file_path)
{
	memset(&wdb_syms, 0, sizeof(wdb_syms));

	wdb_syms[0].elf_path = strdup(file_path);
	if (load_elf_symbols(&wdb_syms[0]) == -1)
		return -1;
	printf("load symbols from %s ok.\n", file_path);

	wdb_sym_idx = 1;
	if (resolve_need_symbols(&wdb_syms[0]) == -1)
		return -1;

	return 0;
}

void wdb_usage(char *proc)
{
	printf("usage: %s <binary_path>\n", proc);
}

int main(int argc, char **argv)
{
	if (argc == 1) {
		wdb_usage(argv[0]);
		return -1;
	}

	target_binary = strdup(argv[1]);
	if (wdb_symbol_init(target_binary) == -1)
		return -1;

	wdb_breakpoints_init();
	wdb_console_init();

	return 0;
}
