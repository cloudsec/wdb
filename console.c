#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <termios.h>
#include <elf.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <errno.h>

#include "wdb.h"
#include "console.h"

extern char *target_binary;
extern int current_bp;
extern int ptrace_state;
extern pid_t c_pid;

struct cmd_console wdb_console_array[] = {
	{wdb_cmd_help, 	CMD_HELP,  CMD_HELP,	"show current command list."},
	{wdb_cmd_help, 	CMD_HELP1, CMD_HELP1,	"show current command list."},
	{wdb_cmd_clear,	CMD_CLEAR, CMD_CLEAR,	"clear the screen."},
	{wdb_cmd_x, 	CMD_X,	   CMD_X_ARG,	"examine memory."},
	{wdb_cmd_b, 	CMD_B,	   CMD_B_ARG,	"set breakpoints."},
	{wdb_cmd_c, 	CMD_C,	   CMD_C_ARG,	"continue the program."},
	{wdb_cmd_d, 	CMD_D,	   CMD_D_ARG,	"delete breakpoints."},
	{wdb_cmd_p, 	CMD_P,	   CMD_P_ARG,	"show symbol values."},
	{wdb_cmd_si, 	CMD_SI,	   CMD_SI_ARG,	"setp to execute one machine instruction."},
	{wdb_cmd_ni, 	CMD_NI,	   CMD_NI_ARG,	"setp to execute one machine instruction, not follow function."},
	{wdb_cmd_r, 	CMD_R,	   CMD_R_ARG,	"run program with args."},
	{wdb_cmd_i, 	CMD_I,	   CMD_I_ARG,	"information command."},
	{wdb_cmd_quit, 	CMD_QUIT,  CMD_QUIT,	"exit the console shell."},
	{NULL,		NULL,	   NULL,	NULL}
};

void wdb_banner(void)
{


}

int wdb_cmd_clear(char *cmd_arg)
{
	return system("clear");
}

int wdb_cmd_help(char *cmd_arg)
{
	int i = 0;

	while (wdb_console_array[i].cmd_name) {	
		printf("%-32s\t\t%s\n", 
			wdb_console_array[i].cmd_arg, wdb_console_array[i].cmd_desc);
		i++;
	}
}

int wdb_cmd_quit(char *cmd_arg)
{
	exit(0);
}

void terminal_icanon_off(int fd)
{
	struct termios old_terminal;

	tcgetattr(fd, &old_terminal);
	old_terminal.c_lflag &= ~ICANON;
	tcsetattr(fd, TCSAFLUSH, &old_terminal);
}

void terminal_icanon_on(int fd)
{
	struct termios old_terminal;

	tcgetattr(fd, &old_terminal);
	old_terminal.c_lflag |= ICANON;
	tcsetattr(fd, TCSAFLUSH, &old_terminal);
}

void handle_ctrl_c(int sig_num)
{
	return ;
}

int console_singal_init(void)
{
	if (signal(SIGINT, handle_ctrl_c) == SIG_ERR) {
		perror("signal");
		return -1;
	}

	return 0;
}

int convert_to_size(char c)
{
	int size = -1;

	switch (c) {
	case 'b':
		size = 1;
		break;
	case 'h':
		size = 2;
		break;
	case 'w':
		size = 4;
		break;
	case 'g':
		size = 8;
		break;
	default:
		printf("wrong unit size for command x.\n");
		break;
	}

	return size;
}

static char cmd_x_fmt[] = {'x','d','u','i','c','s'};
static char cmd_x_size[] = {'b','h','w','g'};

int search_x_fmt(char c)
{
	int i = 0;

	for (i = 0; i < sizeof(cmd_x_fmt)/sizeof(cmd_x_fmt[0]); i++) {
		if (cmd_x_fmt[i] == c)
			return 0;
	}

	return -1;
}

int search_x_size(char c)
{
	int i = 0;

	for (i = 0; i < sizeof(cmd_x_size)/sizeof(cmd_x_size[0]); i++) {
		if (cmd_x_size[i] == c)
			return 0;
	}

	return -1;
}

int is_x_symbol(char *symbol)
{
	char *s = symbol;

	while (*s) {
		if (isalnum(*s) || *s == '_') {
			s++;
			continue;
		}
		return -1;
	}

	return 0;
}

int is_x_addr(char *symbol)
{
	char *s = symbol;

	if (strncmp(s, "0x", 2))
		return -1;

	s += 2;
	if (!*s)
		return -1;

	while (*s) {
		if (isxdigit(*s)) {
			s++;
			continue;
		}
		return -1;
	}

	return 0;
}

int parse_x_addr(struct cmd_x_arg *arg, char *symbol)
{
	if (!is_x_addr(symbol)) {
		arg->x_addr = strtoul(symbol, NULL, 16);
		return 0;
	}

	if (!is_x_symbol(symbol)) {
		uint64_t addr;

		addr = wdb_symbol_addr(symbol);
		if (!addr) {
			printf("find not symbol: %s\n", symbol);
			return -1;
		}
		arg->x_addr = addr;
		strcpy(arg->x_symbol, symbol);
		return 0;
	}

	printf("wrong address format.\n");
	return -1;
}

void set_x_arg_default(struct cmd_x_arg *arg)
{
	arg->x_n = 1;
	arg->x_f = 'x';
	arg->x_u = convert_to_size('w');
}

int parse_x_arg(struct cmd_x_arg *arg, char *cmd)
{
	char tmp[5], *p = tmp, *s;

	/* '/' is not exist, case: x addr */
	s = strchr(cmd, '/');
	if (!s) {
		set_x_arg_default(arg);
		return 0;
	}

	/* case: x/ addr */
	if (*++s == '\0') {
		set_x_arg_default(arg);
		return 0;
	}

	/* get n number. */
	while (*s && isdigit(*s))
		*p++ = *s++;
	*p = '\0';

	arg->x_n = atoi(tmp);
	/* n is empty, case: x/xg addr */
	if (arg->x_n == 0)
		arg->x_n = 1;

	/* f & u is empty. */
	if (*s == '\0') {
		arg->x_f = 'x';
		arg->x_u = convert_to_size('w');
	}
	else {
		if (strlen(s) > 2)
			goto out;

		/* f is exist. */
		if (!search_x_fmt(*s)) {
			arg->x_f = *s;
			if (*(s + 1) != '\0') {
				/* wrong size, case: x/xv. */
				if (search_x_size(*(s + 1)) == -1)
					goto out;

				arg->x_u = convert_to_size(*(s + 1));
				/* wrong format. */
				if (*(s + 2) != '\0')
					goto out;
			}
			else {
				/* u is not exist. */
				arg->x_u = convert_to_size('w');
			}
		}
		else if (!search_x_size(*s)) {
			if (*(s + 1) != '\0')
				goto out;

			arg->x_f = 'x';
			arg->x_u = convert_to_size(*s);
		}
		else {
			/* wrong format. */
			goto out;
		}
	}
	return 0;

out:
	printf("wrong command x format.\n");
	return -1;
}

void print_x_arg(struct cmd_x_arg *arg)
{
	printf("n: %d\tf: %c\tu: %d\n", arg->x_n, arg->x_f, arg->x_u);
	printf("0x%x\t%s\n", arg->x_addr, arg->x_symbol);
}

#define print_data_d(unit, data)				\
{								\
	switch (unit) {						\
	case 1:							\
		printf("%d ", *(char *)(data) & 0xff);		\
		break;						\
	case 2:							\
		printf("%d ", *(short *)(data) & 0xffff);	\
		break;						\
	case 4:							\
		printf("%d ", *(int *)(data) & 0xffffffff);	\
		break;						\
	case 8:							\
		printf("%d ", *(long *)( data));		\
		break;						\
	default:						\
		printf("wrong unit size.\n");			\
		break;						\
	}							\
}								\

#define print_data_c(unit, data)				\
{								\
	switch (unit) {						\
	case 1:							\
		printf("%c ", *(char *)(data) & 0xff);		\
		break;						\
	case 2:							\
		printf("%c ", *(short *)(data) & 0xffff);	\
		break;						\
	case 4:							\
		printf("%c ", *(int *)(data) & 0xffffffff);	\
		break;						\
	case 8:							\
		printf("%c ", *(long *)( data));		\
		break;						\
	default:						\
		printf("wrong unit size.\n");			\
		break;						\
	}							\
}								\

#define print_data_x(unit, data)				\
{								\
	switch (unit) {						\
	case 1:							\
		printf("0x%02x", *(char *)(data) & 0xff);	\
		break;						\
	case 2:							\
		printf("0x%04x ", *(short *)(data) & 0xffff);	\
		break;						\
	case 4:							\
		printf("0x%08x ", *(int *)(data) & 0xffffffff);	\
		break;						\
	case 8:							\
		printf("0x%016lx ", *(long *)( data));		\
		break;						\
	default:						\
		printf("wrong unit size.\n");			\
		break;						\
	}							\
}								\

void display_memory_data(struct cmd_x_arg *arg, void *buf)
{
	int size, n = 0, i, j, k;

	size = arg->x_n * arg->x_u;
	while (n < size) {
		printf("0x%x: ", arg->x_addr + n);
		if (size - n < 16)
			i = (size - n)/arg->x_u;
		else
			i = 16/arg->x_u;

		for (j = 0; j < i; j++) {
			switch (arg->x_f) {
			case 'd':
				print_data_d(arg->x_u, buf + n + j*arg->x_u)
				break;
			case 'c':
				print_data_c(arg->x_u, buf + n + j*arg->x_u)
				break;
			case 'x': 
				print_data_x(arg->x_u, buf + n + j*arg->x_u)
				break;
			default:
				printf("wrong format type.\n");
				return ;
			}
		}
		printf("\n");
		n += 16;
	}
}

int wdb_read_x_memory(pid_t pid, struct cmd_x_arg *arg)
{
	long size;
	void *data;

	size = arg->x_n * arg->x_u;
	if (size < sizeof(long))
		size = sizeof(long);

	data = (void *)calloc(size, 1);
	if (!data)
		return -1;

	if (ptrace_read_memory(pid, arg->x_addr, data, size) == -1)
		goto out;

	display_memory_data(arg, data);

	return 0;
out:
	free(data);
	return -1;
}

int ptrace_is_ready(void)
{
	if (ptrace_state == 0) {
		printf("not attach the process or it has been exitd.\n");
		return -1;
	}

	return 0;
}

/**
 * exame the program memory.
 *
 * x[/nfu] <address|symbol>
 *
 * n - repeat count.
 * f - display format.	'x','d','u','i','c','s'
 * u - unit size.	'b','h','w','g'
 *
 */
int wdb_cmd_x(char *cmd_arg)
{
	struct cmd_x_arg arg;
	char cmd[32], addr[64];

	if (ptrace_is_ready() == -1)
		return -1;

	sscanf(cmd_arg, "%s %s", cmd, addr);
	if (parse_x_addr(&arg, addr) == -1)
		return -1;

	if (parse_x_arg(&arg, cmd) == -1)
		return -1;

	print_x_arg(&arg);
	if (wdb_read_x_memory(c_pid, &arg) == -1)
		return -1;

	return 0;
}

int wdb_read_p_memory(struct cmd_p_arg *arg)
{
	if (ptrace_read_word(c_pid, arg->p_addr, &arg->p_value) == -1)
		return -1;

	return 0;
}

int parse_reg_symbol(struct cmd_p_arg *arg, char *symbol)
{
	arg->p_value = get_reg_value(symbol);
	if (arg->p_value == -1)
		return -1;

        strcpy(arg->p_symbol, symbol);
	return 0;
}

int parse_p_symbol(struct cmd_p_arg *arg, char *symbol)
{
	if (symbol[0] == '$')
		symbol += 1;

        if (!is_x_symbol(symbol)) {
                uint64_t addr;

                addr = wdb_symbol_addr(symbol);
                if (!addr)
                        return parse_reg_symbol(arg, symbol);
                
                arg->p_addr = addr;
                strcpy(arg->p_symbol, symbol);
                return wdb_read_p_memory(arg);
        }

        printf("wrong address format.\n");
        return -1;
}

int parse_p_arg(struct cmd_p_arg *arg, char *cmd_arg)
{
	char *s;

	s = strchr(cmd_arg, '/');
	if (!s) {
		arg->p_f = 'x';
		return 0;
	}

	if (*(s + 1) == '\0' || strlen(s) > 2)
		goto out;

	if (search_x_fmt(*(s + 1)) == -1)
		goto out;

	arg->p_f = *(s + 1);
	return 0;

out:
	printf("wrong format.\n");
	return -1;
}

void print_p_arg(struct cmd_p_arg *arg)
{
	switch (arg->p_f) {
	case 'x':
		printf("%s = 0x%lx\n", arg->p_symbol, arg->p_value);
		break;
	case 'd':
		printf("%s = %d\n", arg->p_symbol, arg->p_value);
		break;
	default:
		break;
	}
}

char operand_array[] = {'+', '-', '*', '/', '%', '(', ')'};

int op_prio(char c)
{
	switch (c) {
	case '+':
	case '-':
		return 1;
	case '*':
	case '/':
	case '%':
		return 2;
	case '(':
	case ')':
		return 3;
	default:
		return 0;
	}
}

int search_operand(char c)
{
	int i;

	for (i = 0; i < sizeof(operand_array)/sizeof(operand_array[0]); i++) {
		if (operand_array[i] == c)
			return 0;
	}

	return -1;
}

#define MAX_OP_NUM		64
#define MAX_VALUE_NUM		(MAX_OP_NUM * 2)

int64_t op_stack[MAX_OP_NUM];
int op_num = 0;

int64_t value_stack[MAX_VALUE_NUM];
int value_num = 0;

int op_flag = 0;

void print_operand(void)
{
	int i;

	printf("op:\t");
	for (i = 0; i < op_num; i++)
		printf("%c ", op_stack[i]);
	printf("\n");
}

void print_value(void)
{
	int i;

	printf("value:\t");
	for (i = 0; i < value_num; i++)
		printf("0x%x ", value_stack[i]);
	printf("\n");
}

int push_operand(char c)
{
	if (op_num >= MAX_OP_NUM)
		return -1;

	op_stack[op_num++] = c;
	return 0;
}

int pop_operand(char *value)
{
	if (op_num <= 0)
		return -1;

	*value = op_stack[op_num - 1];
	op_stack[op_num - 1] = '\0';
	op_num--;

	return 0;
}

int push_value(int64_t value)
{
        if (value_num >= MAX_VALUE_NUM)
                return -1;

        value_stack[value_num++] = value;
        return 0;
}

int pop_value(int64_t *value)
{
        if (value_num <= 0)
                return -1;

        *value = value_stack[value_num - 1];
        value_stack[value_num - 1] = '\0';
	value_num--;
        return 0;
}

int do_push_operand(char c)
{
	int i, n, value;
	char op;

	switch (c) {
	case '(':
		op_flag = 1;
		return push_operand(c);
	case ')':
		for (i = op_num - 1; i >= 0; i--) {
			if (op_stack[i] == '(') {
				op_flag = 0;
				return pop_operand(&op);
			}
			if (pop_operand(&op) == -1)
				return -1;
			if (push_value(op) == -1)
				return -1;
		}
		return -1;
	default:
		n = op_prio(c);
		if (n == 0)
			return -1;

		for (i = op_num - 1; i >= 0; i--) {
			if (op_prio(op_stack[i]) >= n) {
				if (op_flag == 1 && op_stack[i] == '(')
					break;

				if (pop_operand(&op) == -1)
					return -1;
				if (push_value(op) == -1)
					return -1;
			}
		}

		return push_operand(c);
	}

	return 0;
}

int flush_op_stack(void)
{
	char op;
	int i;

	for (i = op_num - 1; i >= 0; i--) {
		if (pop_operand(&op) == -1)
			return -1;
		printf("!%d %c\n", op, op);
		if (push_value((int64_t)op) == -1)
			return -1;
	}

	return 0;
}

void print_status(void)
{
	print_operand();
	print_value();
	printf("-----------------\n");
}

int front_to_suffix(char *src)
{
	char tmp[32], *s, *p;

	memset(tmp, '\0', 32);
	s = src; p = tmp;

	while (*s) {
		if (!search_operand(*s)) {
			*p = 0;
			if (tmp[0] != '\0') {
				if (push_value(strtol(tmp, '\0', 16)) == -1)
					return -1;
				memset(tmp, '\0', 32);
				p = tmp;
				print_status();
			}

			if (do_push_operand(*s) == -1)
				return -1;
			s++;
			print_status();
			continue;
		}
		*p++ = *s++;
	}

	*p = 0;
	if (tmp[0] != '\0') {
		if (push_value(strtol(tmp, '\0', 16)) == -1)
			return -1;
		print_status();
	}

	return flush_op_stack();
}

int wdb_compute_value(char *cmd_arg)
{
	op_num = 0;
	value_num = 0;

	printf("%s\n", cmd_arg);

	if (front_to_suffix(cmd_arg) == -1)
		return -1;

	print_value();
	return 0;
}


/**
 * show the symbol value.
 *
 * p[/f] <address|symbol>
 *
 * f - display format.  'x','d','u','i','c','s'
 * 
 */
int wdb_cmd_p(char *cmd_arg)
{
	struct cmd_p_arg arg;
	char cmd[32], addr[64];

	if (ptrace_is_ready() == -1)
		return -1;

	sscanf(cmd_arg, "%s %s", cmd, addr);

	if (wdb_compute_value(addr) == -1)
		return -1;

	return 0;
	bzero(&arg, sizeof(arg));
	if (parse_p_arg(&arg, cmd) == -1)
		return -1;

        if (!is_x_addr(addr)) {
		printf("%s = %s\n", addr);
                return 0;
        }

	if (parse_p_symbol(&arg, addr) == -1)
		return -1;

	print_p_arg(&arg);
	return 0;
}

/**
 * show the register information.
 *
 * i reg
 * 
 */
int wdb_cmd_i(char *cmd_arg)
{
	wdb_show_regs();

	return 0;
}

#define MAX_ARG_NUM		32
#define MAX_ENV_NUM		128

static char *wdb_args[MAX_ARG_NUM] = {NULL};
static char *wdb_envs[MAX_ENV_NUM] = {NULL};

static int wdb_arg_num = 0;
static int wdb_env_num = 0;

void print_args(void)
{
	int i;

	for (i = 0; i < wdb_arg_num; i++)
		printf("%s\n", wdb_args[i]);
}

int parse_args(char *cmd_arg)
{
	char arg[256], *s, *p;

	s = strchr(cmd_arg, ' ');
	if (!s) {
		wdb_args[0] = NULL;
		return 0;
	}

	p = arg; s++;
	while (*s) {
		if (*s == ' ') {
			*p = 0;
			if (p - arg >= 256) {
				printf("arg too long.\n");
				goto out;
			}
			if (wdb_arg_num >= MAX_ARG_NUM) {
				printf("arg num long.\n");
				goto out;
			}
			wdb_args[wdb_arg_num++] = strdup(arg);
			p = arg; s++;
		}
		else {
			*p++ = *s++;
		}
	}
	*p = 0;

	if (p - arg >= 256) {
		printf("arg too long.\n");
		goto out;
	}
	if (wdb_arg_num >= MAX_ARG_NUM) {
		printf("arg num long.\n");
		goto out;
	}
	wdb_args[wdb_arg_num++] = strdup(arg);
	return 0;

out:
	while (--wdb_arg_num)
		free(wdb_args[wdb_arg_num]);
	return -1;
}

void wdb_run_binary(void)
{
	execve(target_binary, wdb_args, wdb_envs);
}

/**
 * run program with args.
 *
 * r [arg0] .. [argN]
 *
 */
int wdb_cmd_r(char *cmd_arg)
{
	if (parse_args(cmd_arg) == -1)
		return -1;

	wdb_arg_num = 0;
	wdb_env_num = 0;

	if (wdb_attach_program() == -1)
		return -1;

	wdb_fixup_libc_address(c_pid);

	if (wdb_set_breakpoints() == -1)
		goto out;

        if (wdb_continue_program() == -1)
                return -1;

	if (wdb_wait_breakpoints() == -1)
		goto out;

	return 0;
out:
	wdb_detach_program();
	ptrace_state = 0;
	return -1;
}

/**
 * continue the program.
 *
 */
int wdb_cmd_c(char *cmd_arg)
{
	if (ptrace_is_ready() == -1)
		return -1;

	if (wdb_restore_breakpoint() == -1)
		goto out;

        if (wdb_continue_program() == -1)
                goto out;

	if (wdb_wait_breakpoints() == -1)
		goto out;

	return 0;
out:
	wdb_detach_program();
	return -1;
}

int parse_breakpoint(char *cmd_arg)
{
	char cmd[4] = {0}, arg[64] = {0};
	int n;

	sscanf(cmd_arg, "%s %s", cmd, arg);
	if (arg[0] == '\0') {
		print_bps();
		return -1;
	}

	n = alloc_bp();
	if (n == -1)
		return -1;

        if (!is_x_addr(arg)) {
                wdb_bp[n].bp_addr = strtoul(arg, NULL, 16);
                return n;
        }
        else if (!is_x_symbol(arg)) {
		uint64_t addr;

		addr = wdb_symbol_addr(arg);
		if (!addr) {
			printf("find not symbol: %s\n", arg);
			free_bp(n);
			return -1;
		}
		wdb_bp[n].bp_addr = addr;
                strcpy(wdb_bp[n].bp_symbol, arg);
                return n;
        }
	else {
		return -1;
	}

        return -1;
}

/**
 * set breakpoints.
 *
 * b <address|symbol>
 *
 */
int wdb_cmd_b(char *cmd_arg)
{
	int n;

	n = parse_breakpoint(cmd_arg);
	if (n == -1)
		goto out;

	if (!ptrace_state) 
		return 0;

	wdb_fixup_libc_address(c_pid);
	if (wdb_set_breakpoint(&wdb_bp[n]) == -1)
		goto out;

	return 0;
out:
	return -1;
}

int wdb_search_bp(char *cmd_arg)
{
        char cmd[4], arg[64];
        int n = -1;

        sscanf(cmd_arg, "%s %s", cmd, arg);
	if (arg[0] == '\0')
		return -1;
	
        if (!is_x_addr(arg)) {
		n = search_bp_address(strtoul(arg, NULL, 16));
		if (n == -1) 
			goto out;
	}
	else if (!is_x_symbol(arg)) {
		n = search_bp_symbol(arg);
		if (n == -1)
			goto out;
	}
	else {
		goto out;
	}

	return n;
out:
	printf("not found bp for %s.\n", arg);
	return -1;
}

/**
 * delete breakpoints.
 *
 * d <address|symbol>
 *
 */
int wdb_cmd_d(char *cmd_arg)
{
	int n;

	n = wdb_search_bp(cmd_arg);
	if (n == -1)
		return -1;

	if (ptrace_state == 1) {
		if (wdb_delete_breakpoint(n, 1) == -1)
			goto out;
	}

	if (delete_bp_array(n) == -1) {
		printf("delete bp %d failed.\n", n);
		return -1;
	}

	return 0;
out:
	wdb_detach_program();
	return -1;
}

/**
 * step to execute one machine instruction.
 *
 * si
 *
 */
int wdb_cmd_si(char *cmd_arg)
{
	if (ptrace_is_ready() == -1)
		return -1;

	wdb_fixup_libc_address(c_pid);
	if (wdb_step_instruction() == -1)
		goto out;

	return 0;
out:
	wdb_detach_program();
	return -1;
}

/**
 * step to execute one machine instruction, 
 * if it's a function, don't follow it's instruction.
 *
 * ni
 *
 */
int wdb_cmd_ni(char *cmd_arg)
{
	if (ptrace_is_ready() == -1)
		return -1;

	if (wdb_ni_instruction() == -1)
		goto out;

	return 0;
out:
	wdb_detach_program();
	return -1;
}

int parse_console_cmd(char *cmd_name)
{
	char *s = cmd_name, *cmd_arg;
	int i = 0;

	/* skip blank charactors. */
	while (*s) {
		if (isblank(*s)) {
			s++;
			continue;
		}
		break;
	}
	if (*s == '\0')
		return -1;

	cmd_arg = strdup(s);
	s = strchr(cmd_arg, ' ');
	if (s)
		*s = 0;

	s = strchr(cmd_arg, '/');
	if (s)
		*s = 0;

	while (wdb_console_array[i].cmd_name) {
		if (!strcmp(wdb_console_array[i].cmd_name, cmd_arg)) {
			free(cmd_arg);
			return i;
		}
		i++;
	}
	
	free(cmd_arg);
	return -1;
}

int get_cmd_line(char *cmd_buf)
{
	char c;
	int i = 0;

	/* first turn off the terminal icanon mode. */
	terminal_icanon_off(0);
	for (;;) {
		scanf("%c", &c);

		switch (c) {
		case '\n':
			goto out;
		default:
			if (i >= CMD_MAX_SIZE) {
				printf("command size too long.\n");
				goto out_term;
			}
			cmd_buf[i++] = c;
		}
	}

out:
	cmd_buf[i] = '\0';
	terminal_icanon_on(0);
	return 0;

out_term:
	terminal_icanon_on(0);
	return -1;
}

int wdb_console_enter(void)
{
	char cmd[CMD_MAX_SIZE];
	int i;

	for (;;) {
		printf("%s", CMD_BANNER);

		memset(cmd, '\0', CMD_MAX_SIZE);
		if (get_cmd_line(cmd) == -1)
			continue;

		i = parse_console_cmd(cmd);
		if (i == -1)
			continue;

		wdb_console_array[i].do_cmd(cmd);
	}
}

int wdb_console_init(void)
{
	if (console_singal_init() == -1)
		return -1;

	wdb_banner();
	wdb_console_enter();

	return 0;
}
