/*
 * iptables userspace extension for FULLCONENAT target.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <stdio.h>
#include <string.h>
#include <xtables.h>
#include <linux/netfilter/nf_nat.h>

static void FULLCONENAT_help(void)
{
	printf("FULLCONENAT target options:\n"
	       "  (no options)\n"
	       "\n"
	       "  Full Cone NAT (NAT1): Maps internal host:port to a fixed\n"
	       "  external port. Any external host can send packets to the\n"
	       "  mapped port and they will be forwarded to the internal host.\n");
}

static int FULLCONENAT_parse(int c, char **argv, int invert,
			     unsigned int *flags,
			     const void *entry,
			     struct xt_entry_target **target)
{
	return 0;
}

static void FULLCONENAT_check(unsigned int flags)
{
}

static struct xtables_target fullconenat_tg_reg = {
	.name		= "FULLCONENAT",
	.version	= XTABLES_VERSION,
	.family		= NFPROTO_UNSPEC,
	.size		= XT_ALIGN(sizeof(int)),
	.userspacesize	= XT_ALIGN(sizeof(int)),
	.help		= FULLCONENAT_help,
	.parse		= FULLCONENAT_parse,
	.final_check	= FULLCONENAT_check,
};

static void init(void) __attribute__((constructor));
static void init(void)
{
	xtables_register_target(&fullconenat_tg_reg);
}
