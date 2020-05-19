/*
 * "XOR" target extension for xtables-addons
 * Copyright © Andrew Smith, 2014
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License; either
 * version 2 of the License, or any later version, as published by the
 * Free Software Foundation.
 */
#include <netinet/in.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <xtables.h>
#include <linux/netfilter.h>
#include <errno.h>
#include "xt_XOR.h"

enum {
    FLAGS_KEY = 1 << 0,
    FLAGS_KEYS = 1 << 1,
};

enum {
    O_XOR_KEY = 0,
    O_XOR_KEYS,
};

static const struct option xor_opts[] = {
    {.name = "key", .has_arg = true, .val = O_XOR_KEY},
    {.name = "keys", .has_arg = true, .val = O_XOR_KEYS},
    {},
};

static void xor_help(void)
{
    printf(
            "XOR target options:\n"
            "    --key <byte>\n"
            "    --keys \"string\"\n"
          );
}

    static int
xor_parse(int c, char **argv, int invert, unsigned int *flags,
        const void *entry, struct xt_entry_target **target)
{
    struct xt_xor_info *info = (void *)(*target)->data;
    unsigned long k;
    const char *s = optarg;
    switch (c) {
        case O_XOR_KEY:
            k = strtoul(s, NULL, 16);
            if ( errno == EINVAL || errno == ERANGE || k > 0xff ) {
                xtables_error(PARAMETER_PROBLEM, "XOR: key is one byte, like 0xab");
            }
            info->key = (unsigned char)k;
            *flags |= FLAGS_KEY;
            return true;
        case O_XOR_KEYS:
            if (strlen(s) <= XT_XOR_MAX_KEY_SIZE) {
                strncpy(info->keys, s, XT_XOR_MAX_KEY_SIZE);
                *flags |= FLAGS_KEYS;
                return true;
            }
            xtables_error(PARAMETER_PROBLEM, "XOR: keys length > 64 bytes");
    }
    return false;
}
static void xor_check(unsigned int flags)
{
    if ((flags & FLAGS_KEY) || (flags & FLAGS_KEYS))
        return;
    xtables_error(PARAMETER_PROBLEM, "XOR: "
                "--key or --keys is required.");
}

    static void
xor_print(const void *entry, const struct xt_entry_target *target,
        int numeric)
{
    const struct xt_xor_info *info = (const void *)target->data;
    if (info->key > 0)
        printf("  --key 0x%x ",info->key);
    if (info->keys[0] > 0)
        printf("  --keys \"%s\" ",info->keys);
}

    static void
xor_save(const void *entry, const struct xt_entry_target *target)
{
    const struct xt_xor_info *info = (const void *)target->data;
    if (info->key > 0)
        printf("  --key 0x%x ",info->key);
    if (info->keys[0] > 0)
        printf("  --keys \"%s\" ",info->keys);
}

static struct xtables_target xor_reg[] = {
    {
        .version       = XTABLES_VERSION,
        .name          = "XOR",
        .revision      = 0,
        .family        = NFPROTO_IPV4,
        .size          = XT_ALIGN(sizeof(struct xt_xor_info)),
        .userspacesize = XT_ALIGN(sizeof(struct xt_xor_info)),
        .help          = xor_help,
        .parse         = xor_parse,
        .final_check   = xor_check,
        .print         = xor_print,
        .save          = xor_save,
        .extra_opts    = xor_opts,
    },
};

static void _init(void)
{
    xtables_register_targets(xor_reg,
            sizeof(xor_reg) / sizeof(*xor_reg));
}
