// SPDX-License-Identifier: GPL-2.0-only
/*
 * Unified Full Cone NAT - module entry point
 *
 * iptables (xt_target) registration is conditional on CONFIG_NETFILTER_XTABLES
 * so that fw4-only builds don't pull in kmod-nf-ipt.
 */

#include "fullcone.h"

#if IS_ENABLED(CONFIG_NETFILTER_XTABLES)
#include <linux/netfilter/x_tables.h>

/*
 * Target info struct for userspace communication.
 * Kept empty for ABI compatibility with existing libipt_FULLCONENAT.
 */
struct xt_fullconenat_tginfo {
	__u32 unused;
};

static unsigned int
fullcone_xt_target(struct sk_buff *skb, const struct xt_action_param *par)
{
	sa_family_t family = xt_family(par);
	unsigned int hooknum = xt_hooknum(par);

	if (hooknum == NF_INET_POST_ROUTING)
		return fullcone_do_postrouting(skb, xt_out(par), family);
	else if (hooknum == NF_INET_PRE_ROUTING)
		return fullcone_do_prerouting(skb, family);

	return NF_ACCEPT;
}

static int fullcone_xt_checkentry(const struct xt_tgchk_param *par)
{
	return nf_ct_netns_get(par->net, par->family);
}

static void fullcone_xt_destroy(const struct xt_tgdtor_param *par)
{
	nf_ct_netns_put(par->net, par->family);
}

static struct xt_target fullcone_xt_targets[] __read_mostly = {
	{
		.name		= "FULLCONENAT",
		.revision	= 0,
		.family		= NFPROTO_IPV4,
		.target		= fullcone_xt_target,
		.checkentry	= fullcone_xt_checkentry,
		.destroy	= fullcone_xt_destroy,
		.table		= "nat",
		.hooks		= (1 << NF_INET_PRE_ROUTING) |
				  (1 << NF_INET_POST_ROUTING),
		.targetsize	= sizeof(struct xt_fullconenat_tginfo),
		.me		= THIS_MODULE,
	},
	{
		.name		= "FULLCONENAT",
		.revision	= 0,
		.family		= NFPROTO_IPV6,
		.target		= fullcone_xt_target,
		.checkentry	= fullcone_xt_checkentry,
		.destroy	= fullcone_xt_destroy,
		.table		= "nat",
		.hooks		= (1 << NF_INET_PRE_ROUTING) |
				  (1 << NF_INET_POST_ROUTING),
		.targetsize	= sizeof(struct xt_fullconenat_tginfo),
		.me		= THIS_MODULE,
	},
};

static int fullcone_xt_init(void)
{
	return xt_register_targets(fullcone_xt_targets,
				   ARRAY_SIZE(fullcone_xt_targets));
}

static void fullcone_xt_exit(void)
{
	xt_unregister_targets(fullcone_xt_targets,
			      ARRAY_SIZE(fullcone_xt_targets));
}

#else /* !CONFIG_NETFILTER_XTABLES */

static inline int fullcone_xt_init(void) { return 0; }
static inline void fullcone_xt_exit(void) {}

#endif /* CONFIG_NETFILTER_XTABLES */

/*
 * Module init: core helpers → xt targets (if available) → nft expression.
 * Both xt and nft registration failures are non-fatal when the other succeeds.
 */
static int __init fullcone_init(void)
{
	int ret;
	bool has_xt = false, has_nft = false;

	ret = fullcone_core_init();
	if (ret)
		return ret;

	ret = fullcone_xt_init();
	if (ret) {
		pr_info("fullcone: xt target not registered (%d)\n", ret);
	} else {
		has_xt = true;
	}

	ret = fullcone_nft_init();
	if (ret) {
		pr_info("fullcone: nft expression not registered (%d)\n", ret);
	} else {
		has_nft = true;
	}

	if (!has_xt && !has_nft) {
		pr_err("fullcone: neither xt nor nft registered, aborting\n");
		fullcone_core_exit();
		return -ENODEV;
	}

	pr_info("fullcone: loaded (xt=%s nft=%s)\n",
		has_xt ? "yes" : "no", has_nft ? "yes" : "no");
	return 0;
}

static void __exit fullcone_exit(void)
{
	fullcone_nft_exit();
	fullcone_xt_exit();
	fullcone_core_exit();
}

module_init(fullcone_init);
module_exit(fullcone_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("TurboACC Contributors");
MODULE_DESCRIPTION("Unified Full Cone NAT (iptables + nftables)");
MODULE_ALIAS_NFT_EXPR("fullcone");
