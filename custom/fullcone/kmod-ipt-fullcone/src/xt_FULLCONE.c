/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * xt_FULLCONE.c - iptables/ip6tables target wrapper for the unified fullcone
 * NAT engine.
 *
 * Builds a self-contained kernel module that does NOT depend on any nftables
 * symbol or module. The engine source is included from this very translation
 * unit (see Kbuild) so all engine symbols are file-static and never escape
 * this .ko.
 */

#include <linux/module.h>
#include <linux/version.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/netfilter/x_tables.h>

#include <net/netfilter/nf_nat.h>

#include "fc_engine.h"
#include "xt_FULLCONE.h"

/*
 * Pull the entire engine into THIS translation unit. All engine symbols are
 * `static`, so after compilation they live exclusively inside xt_FULLCONE.ko
 * and cannot collide with — or be reached from — nft_FULLCONE.ko.
 */
#include "fc_engine.c"

/*
 * Build the engine's fc_range from the user-supplied target info. The
 * userspace iptables extension passes a struct xt_fullcone_tginfo (defined in
 * xt_FULLCONE.h) — a small, version-stable structure that does not depend on
 * any in-tree NAT struct layout.
 */
static void fc_build_range(const struct xt_fullcone_tginfo *info, u8 family,
			   struct fc_range *out)
{
	memset(out, 0, sizeof(*out));
	out->flags    = info->flags;
	out->family   = family;
	out->min_addr = info->min_addr;
	out->max_addr = info->max_addr;
	out->min_port = info->min_port;
	out->max_port = info->max_port;
}

/* ----- IPv4 target ------------------------------------------------------- */

static unsigned int fullcone_tg4(struct sk_buff *skb,
				 const struct xt_action_param *par)
{
	const struct xt_fullcone_tginfo *info = par->targinfo;
	struct fc_range range;

	fc_build_range(info, NFPROTO_IPV4, &range);
	return fc_engine_eval(skb, xt_hooknum(par), xt_out(par), &range);
}

static int fullcone_tg_check(const struct xt_tgchk_param *par)
{
	int err;

	err = nf_ct_netns_get(par->net, par->family);
	if (err)
		return err;
	fc_engine_take(par->net);
	return 0;
}

static void fullcone_tg_destroy(const struct xt_tgdtor_param *par)
{
	fc_engine_drop(par->net);
	nf_ct_netns_put(par->net, par->family);
}

/* ----- IPv6 target ------------------------------------------------------- */

#if IS_ENABLED(CONFIG_IPV6)
static unsigned int fullcone_tg6(struct sk_buff *skb,
				 const struct xt_action_param *par)
{
	const struct xt_fullcone_tginfo *info = par->targinfo;
	struct fc_range range;

	fc_build_range(info, NFPROTO_IPV6, &range);
	return fc_engine_eval(skb, xt_hooknum(par), xt_out(par), &range);
}
#endif

/* ----- xt_target table --------------------------------------------------- */

static struct xt_target fullcone_tg_reg[] __read_mostly = {
	{
		.name       = "FULLCONE",
		.family     = NFPROTO_IPV4,
		.revision   = 0,
		.target     = fullcone_tg4,
		.targetsize = sizeof(struct xt_fullcone_tginfo),
		.table      = "nat",
		.hooks      = (1 << NF_INET_PRE_ROUTING) |
			      (1 << NF_INET_POST_ROUTING),
		.checkentry = fullcone_tg_check,
		.destroy    = fullcone_tg_destroy,
		.me         = THIS_MODULE,
	},
#if IS_ENABLED(CONFIG_IPV6)
	{
		.name       = "FULLCONE",
		.family     = NFPROTO_IPV6,
		.revision   = 0,
		.target     = fullcone_tg6,
		.targetsize = sizeof(struct xt_fullcone_tginfo),
		.table      = "nat",
		.hooks      = (1 << NF_INET_PRE_ROUTING) |
			      (1 << NF_INET_POST_ROUTING),
		.checkentry = fullcone_tg_check,
		.destroy    = fullcone_tg_destroy,
		.me         = THIS_MODULE,
	},
#endif
};

/* ----- Module init / exit ------------------------------------------------ */

static int __init fullcone_tg_init(void)
{
	int err;

	err = fc_engine_init();
	if (err)
		return err;

	err = xt_register_targets(fullcone_tg_reg, ARRAY_SIZE(fullcone_tg_reg));
	if (err) {
		fc_engine_exit();
		return err;
	}
	return 0;
}

static void __exit fullcone_tg_exit(void)
{
	xt_unregister_targets(fullcone_tg_reg, ARRAY_SIZE(fullcone_tg_reg));
	fc_engine_exit();
}

module_init(fullcone_tg_init);
module_exit(fullcone_tg_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Unified fullcone NAT (iptables target)");
MODULE_AUTHOR("turboacc");
MODULE_ALIAS("ipt_FULLCONE");
#if IS_ENABLED(CONFIG_IPV6)
MODULE_ALIAS("ip6t_FULLCONE");
#endif
