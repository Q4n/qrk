#include <stdio.h>
#include <dirent.h>
#include <sys/syscall.h>

void do_open_test(void)
{
	syscall(SYS_open, "ihavenodreamecho 1 >/tmp/mys", 200, 0xdeadbeef);
	while (1)
		;
}

int main()
{
	do_open_test();
}
