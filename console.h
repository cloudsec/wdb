#ifndef WDB_CONSOLE_H
#define WDB_CONSOLE_H

#include <stdint.h>

struct cmd_console {
	int (*do_cmd)(char *cmd_arg);
	char *cmd_name;
	char *cmd_arg;
	char *cmd_desc;
};

#define CMD_HELP		"help"
#define CMD_HELP1		"?"
#define CMD_CLEAR		"clear"
#define CMD_QUIT		"quit"

#define CMD_X			"x"
#define CMD_X_ARG		"x/[nfu] <address|symbol>"

#define CMD_R			"r"
#define CMD_R_ARG		"r [arg0] ... [argN]"

#define CMD_B			"b"
#define CMD_B_ARG		"b <address|symbol>"

#define CMD_C			"c"
#define CMD_C_ARG		"c"

#define CMD_D			"d"
#define CMD_D_ARG		"d <address|symbol>"

#define CMD_NI			"ni"
#define CMD_NI_ARG		"ni"

#define CMD_SI			"si"
#define CMD_SI_ARG		"si"

#define CMD_P			"p"
#define CMD_P_ARG		"p/[f] <address|symbol>"

#define CMD_I			"i"
#define CMD_I_ARG		"i <reg>"

#define CMD_BANNER		"wdb>"
#define CMD_MAX_SIZE		64

struct cmd_x_arg {
	int x_n;
	int x_f;
	int x_u;
	char x_symbol[64];
	uint64_t x_addr;
};

struct cmd_p_arg {
	int p_f;
	char p_symbol[64];
	uint64_t p_addr;
	int64_t p_value;
};

int wdb_cmd_help(char *cmd_arg);
int wdb_cmd_clear(char *cmd_arg);
int wdb_cmd_x(char *cmd_arg);
int wdb_cmd_b(char *cmd_arg);
int wdb_cmd_c(char *cmd_arg);
int wdb_cmd_d(char *cmd_arg);
int wdb_cmd_r(char *cmd_arg);
int wdb_cmd_p(char *cmd_arg);
int wdb_cmd_i(char *cmd_arg);
int wdb_cmd_si(char *cmd_arg);
int wdb_cmd_ni(char *cmd_arg);
int wdb_cmd_quit(char *cmd_arg);
int wdb_console_init(void);

#endif
