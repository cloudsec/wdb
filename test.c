#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>

int a = 1;
static int b = 2;
char *c = "hello,world.\n";

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
			printf("%lx\n", addr1);
                        return addr1;
                }
        }

        fclose(fp);
        return 0;
}

int test(int c)
{
	printf("%d\n", c);
}

void test1(int a)
{
	test(a);
}

void test2(void)
{
	int i;

	for (i = 0; i < 3; i++)
		test1(i);
}

int test3(int a)
{
	int b = 1;

	return  a + b;
}

void test4(void)
{
	int a = 1, b;

	b = test3(a);
}

void test5(void)
{
	test4();
}

int main()
{
	printf("hello,world %d %d.\n", '\0', 0);

	test5();
	get_libc_base(getpid());
	test2();
	//sleep(30);
	return 0;
}
