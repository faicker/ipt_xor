#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/tcp.h>
#include <net/checksum.h>

#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter/x_tables.h>
#include "xt_XOR.h"

MODULE_AUTHOR("faicker.mo <faicker.mo@gmail.com>");
MODULE_DESCRIPTION("IP tables XOR module");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_XOR");

void transform(char *buffer, uint32_t len, unsigned char key)
{
    unsigned j;
    unsigned long *p = (unsigned long *)buffer;
    unsigned long kl = 0;
    const unsigned long_size = sizeof(unsigned long);
    for ( j = 0;j < long_size;j++ ) {
        kl = (kl << 8) + key;
    }
    while ( len > long_size ) {
        *p ^= kl;
        p++;
        len -= long_size;
    }
    buffer = (char *)p;
    while ( len > 0 ) {
        *buffer ^= key;
        buffer++;
        len -= 1;
    }
}

    static unsigned int
xt_xor_target(struct sk_buff *pskb, const struct xt_target_param *par)
{
    const struct xt_xor_info *info = par->targinfo;
    struct iphdr *iph;
    /* To avoid warnings */
    struct tcphdr *tcph = 0;
    struct udphdr *udph = 0;
    unsigned char *buf_pos;
    int data_len;

    iph = ip_hdr(pskb);
    if (!skb_make_writable(pskb, ntohs(iph->tot_len)))
        return NF_DROP;

    iph = ip_hdr(pskb);
    buf_pos = pskb->data;
    buf_pos += iph->ihl*4;

    if (iph->protocol == IPPROTO_TCP) {
        tcph = (struct tcphdr *) buf_pos;
        buf_pos += tcph->doff*4;
        data_len = ntohs(iph->tot_len) - iph->ihl*4 - tcph->doff*4;
    } else if (iph->protocol == IPPROTO_UDP) {
        udph = (struct udphdr *) buf_pos;
        buf_pos += sizeof(struct udphdr);
        data_len = ntohs(udph->len)-sizeof(struct udphdr);
    } else {
        return XT_CONTINUE;
    }
    transform(buf_pos, data_len, info->key);
    return XT_CONTINUE;
}

static bool xt_xor_checkentry(const struct xt_tgchk_param *par)
{
    if (strcmp(par->table, "mangle")) {
        printk(KERN_WARNING "XOR: can only be called from"
                "\"mangle\" table, not \"%s\"\n", par->table);
        return false;
    }

    return true;
}

static struct xt_target xt_xor = {
    .name = "XOR",
    .revision = 0,
    .family = NFPROTO_IPV4,
    .table = "mangle",
    .target = xt_xor_target,
    .targetsize = sizeof(struct xt_xor_info),
    .checkentry = xt_xor_checkentry,
    .me = THIS_MODULE,
};

static int __init xor_tg_init(void)
{
    return xt_register_target(&xt_xor);
}

static void __exit xor_target_exit(void)
{
    xt_unregister_target(&xt_xor);
}

module_init(xor_tg_init);
module_exit(xor_target_exit);
