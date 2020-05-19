#include <linux/version.h>
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
MODULE_DESCRIPTION("iptables XOR module");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_XOR");

static inline void transform_k(char *buffer, uint32_t len, unsigned char key)
{
    unsigned i;
    for (i = 0;i < len;i++) {
        buffer[i] ^= key;
    }
}

static inline void transform_ks(char *buffer, uint32_t len, const char* keys)
{
    unsigned key_len = strlen(keys);
    unsigned i;
    for (i = 0;i < len;i++) {
        buffer[i] ^= keys[i % key_len];
    }
}

static inline void transform(char *buffer, uint32_t len, const struct xt_xor_info *info)
{
    if (info->keys[0] > 0)
        transform_ks(buffer, len, info->keys);
    else
        transform_k(buffer, len, info->key);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0)
    static unsigned int
xt_xor_target(struct sk_buff *skb, const struct xt_action_param *par)
#else
    static unsigned int
xt_xor_target(struct sk_buff *skb, const struct xt_target_param *par)
#endif
{
    const struct xt_xor_info *info = par->targinfo;
    struct iphdr *iph;
    struct tcphdr *tcph = NULL;
    struct udphdr *udph = NULL;
    unsigned char *buf_pos;
    int data_len, tcplen, udplen;

    iph = ip_hdr(skb);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,3,0)
    if (unlikely(skb_ensure_writable(skb, ntohs(iph->tot_len))))
#else
    if (unlikely(!skb_make_writable(skb, ntohs(iph->tot_len))))
#endif
        return NF_DROP;

    iph = ip_hdr(skb);
    buf_pos = skb->data;
    buf_pos += iph->ihl*4;
    
    if (iph->protocol == IPPROTO_TCP) {
        tcph = (struct tcphdr *)buf_pos;
        buf_pos += tcph->doff*4;
        tcplen = skb->len - iph->ihl*4;
        data_len =  tcplen - tcph->doff*4;
        if (unlikely(data_len < 0)) {
            return NF_DROP;
        }
        transform(buf_pos, data_len, info);
        if (skb->ip_summed != CHECKSUM_PARTIAL) {
            tcph->check = 0;
            tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
                                       tcplen, IPPROTO_TCP,
                                       csum_partial((char *)tcph, tcplen, 0));
        }
    } else if (iph->protocol == IPPROTO_UDP) {
        udph = (struct udphdr *)buf_pos;
        buf_pos += sizeof(struct udphdr);
        udplen = skb->len - iph->ihl*4;
        data_len = udplen - sizeof(struct udphdr);
        if (unlikely(data_len < 0)) {
            return NF_DROP;
        }
        transform(buf_pos, data_len, info);
        if (skb->ip_summed != CHECKSUM_PARTIAL) {
            udph->check = 0;
            udph->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
                                       udplen, IPPROTO_UDP,
                                       csum_partial((char *)udph, udplen, 0));
        }
    }
    return XT_CONTINUE;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35)
static int xt_xor_checkentry(const struct xt_tgchk_param *par)
{
    if (strcmp(par->table, "mangle")) {
        printk(KERN_WARNING "XOR: can only be called from"
                "\"mangle\" table, not \"%s\"\n", par->table);
        return -EINVAL;
    }

    return 0;
}
#else
static bool xt_xor_checkentry(const struct xt_tgchk_param *par)
{
    if (strcmp(par->table, "mangle")) {
        printk(KERN_WARNING "XOR: can only be called from"
                "\"mangle\" table, not \"%s\"\n", par->table);
        return false;
    }

    return true;
}
#endif

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
