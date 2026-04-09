/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * nft_fullcone.c - nftables expression wrapper for the unified fullcone NAT
 * engine.
 *
 * Builds a self-contained kernel module that does NOT depend on any iptables
 * (xtables) symbol or module. The engine source is `#include`-d directly into
 * this translation unit (see Kbuild) so all engine symbols are file-static
 * and never escape this .ko.
 *
 * The expression's user-facing name is `fullcone`. Use it from nft like any
 * other stateful object — typical placement is in the postrouting NAT chain:
 *
 *   table inet nat {
 *       chain postrouting {
 *           type nat hook postrouting priority srcnat;
 *           oifname "wan" fullcone
 *       }
 *   }
 *
 * No prerouting rule is needed: inbound DNAT happens automatically via the
 * conntrack expectation system installed by the engine.
 */

#include <linux/module.h>
#include <linux/version.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <net/netfilter/nf_tables.h>
#include <net/netfilter/nf_tables_ipv4.h>
#include <net/netfilter/nf_tables_ipv6.h>
#include <net/netfilter/nf_nat.h>

#include "fc_engine.h"

/*
 * Pull the entire engine into THIS translation unit. All engine symbols are
 * `static`, so after compilation they live exclusively inside nft_FULLCONE.ko
 * and cannot collide with — or be reached from — xt_FULLCONE.ko.
 */
#include "fc_engine.c"

/* ------------------------------------------------------------------------- */
/* Netlink attribute layout                                                  */
/* ------------------------------------------------------------------------- */

enum nft_fullcone_attributes {
	NFTA_FULLCONE_UNSPEC,
	NFTA_FULLCONE_FLAGS,		/* NLA_U32: NF_NAT_RANGE_* */
	NFTA_FULLCONE_REG_PROTO_MIN,	/* NLA_U32: nft_register */
	NFTA_FULLCONE_REG_PROTO_MAX,	/* NLA_U32: nft_register */
	NFTA_FULLCONE_REG_ADDR_MIN,	/* NLA_U32: nft_register */
	NFTA_FULLCONE_REG_ADDR_MAX,	/* NLA_U32: nft_register */
	__NFTA_FULLCONE_MAX
};
#define NFTA_FULLCONE_MAX	(__NFTA_FULLCONE_MAX - 1)

static const struct nla_policy nft_fullcone_policy[NFTA_FULLCONE_MAX + 1] = {
	[NFTA_FULLCONE_FLAGS]         = { .type = NLA_U32 },
	[NFTA_FULLCONE_REG_PROTO_MIN] = { .type = NLA_U32 },
	[NFTA_FULLCONE_REG_PROTO_MAX] = { .type = NLA_U32 },
	[NFTA_FULLCONE_REG_ADDR_MIN]  = { .type = NLA_U32 },
	[NFTA_FULLCONE_REG_ADDR_MAX]  = { .type = NLA_U32 },
};

/* ------------------------------------------------------------------------- */
/* Per-rule private data                                                     */
/* ------------------------------------------------------------------------- */

struct nft_fullcone {
	u32	flags;
	u8	sreg_proto_min;
	u8	sreg_proto_max;
	u8	sreg_addr_min;
	u8	sreg_addr_max;
};

/* ------------------------------------------------------------------------- */
/* Validate / init / destroy                                                 */
/* ------------------------------------------------------------------------- */

static int nft_fullcone_validate(const struct nft_ctx *ctx,
				 const struct nft_expr *expr,
				 const struct nft_data **data)
{
	int err;

	err = nft_chain_validate_dependency(ctx->chain, NFT_CHAIN_T_NAT);
	if (err < 0)
		return err;

	return nft_chain_validate_hooks(ctx->chain,
					(1 << NF_INET_PRE_ROUTING) |
					(1 << NF_INET_POST_ROUTING));
}

/* Compatibility shim for nft_parse_register_load: pre-6.1 it took just
 * (attr, sreg, len); 6.1+ takes (ctx, attr, sreg, len). We hide the
 * difference behind a single helper so the rest of the file stays clean. */
static inline int fc_nft_parse_reg_load(const struct nft_ctx *ctx,
					const struct nlattr *attr,
					u8 *sreg, unsigned int len)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
	return nft_parse_register_load(ctx, attr, sreg, len);
#else
	return nft_parse_register_load(attr, sreg, len);
#endif
}

static int nft_fullcone_common_init(const struct nft_ctx *ctx,
				    const struct nft_expr *expr,
				    const struct nlattr *const tb[])
{
	struct nft_fullcone *priv = nft_expr_priv(expr);
	unsigned int plen;
	int err;

	if (tb[NFTA_FULLCONE_FLAGS]) {
		priv->flags = ntohl(nla_get_be32(tb[NFTA_FULLCONE_FLAGS]));
		if (priv->flags & ~NF_NAT_RANGE_MASK)
			return -EOPNOTSUPP;
	}

	plen = sizeof_field(struct nf_nat_range, min_proto.all);
	if (tb[NFTA_FULLCONE_REG_PROTO_MIN]) {
		err = fc_nft_parse_reg_load(ctx, tb[NFTA_FULLCONE_REG_PROTO_MIN],
					    &priv->sreg_proto_min, plen);
		if (err < 0)
			return err;
		if (tb[NFTA_FULLCONE_REG_PROTO_MAX]) {
			err = fc_nft_parse_reg_load(ctx,
						    tb[NFTA_FULLCONE_REG_PROTO_MAX],
						    &priv->sreg_proto_max, plen);
			if (err < 0)
				return err;
		} else {
			priv->sreg_proto_max = priv->sreg_proto_min;
		}
		priv->flags |= NF_NAT_RANGE_PROTO_SPECIFIED;
	}

	if (tb[NFTA_FULLCONE_REG_ADDR_MIN]) {
		plen = (ctx->family == NFPROTO_IPV6) ? sizeof(struct in6_addr)
						     : sizeof(__be32);
		err = fc_nft_parse_reg_load(ctx, tb[NFTA_FULLCONE_REG_ADDR_MIN],
					    &priv->sreg_addr_min, plen);
		if (err < 0)
			return err;
		if (tb[NFTA_FULLCONE_REG_ADDR_MAX]) {
			err = fc_nft_parse_reg_load(ctx,
						    tb[NFTA_FULLCONE_REG_ADDR_MAX],
						    &priv->sreg_addr_max, plen);
			if (err < 0)
				return err;
		} else {
			priv->sreg_addr_max = priv->sreg_addr_min;
		}
		priv->flags |= NF_NAT_RANGE_MAP_IPS;
	}

	err = nf_ct_netns_get(ctx->net, ctx->family);
	if (err < 0)
		return err;
	fc_engine_take(ctx->net);
	return 0;
}

static void nft_fullcone_common_destroy(const struct nft_ctx *ctx,
					const struct nft_expr *expr)
{
	fc_engine_drop(ctx->net);
	nf_ct_netns_put(ctx->net, ctx->family);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)
static int nft_fullcone_dump(struct sk_buff *skb,
			     const struct nft_expr *expr, bool reset)
#else
static int nft_fullcone_dump(struct sk_buff *skb,
			     const struct nft_expr *expr)
#endif
{
	const struct nft_fullcone *priv = nft_expr_priv(expr);

	if (priv->flags &&
	    nla_put_be32(skb, NFTA_FULLCONE_FLAGS, htonl(priv->flags)))
		goto nla_put_failure;

	if (priv->sreg_proto_min) {
		if (nft_dump_register(skb, NFTA_FULLCONE_REG_PROTO_MIN,
				      priv->sreg_proto_min) ||
		    nft_dump_register(skb, NFTA_FULLCONE_REG_PROTO_MAX,
				      priv->sreg_proto_max))
			goto nla_put_failure;
	}

	if (priv->sreg_addr_min) {
		if (nft_dump_register(skb, NFTA_FULLCONE_REG_ADDR_MIN,
				      priv->sreg_addr_min) ||
		    nft_dump_register(skb, NFTA_FULLCONE_REG_ADDR_MAX,
				      priv->sreg_addr_max))
			goto nla_put_failure;
	}

	return 0;
nla_put_failure:
	return -1;
}

/* ------------------------------------------------------------------------- */
/* Build fc_range from per-rule data + register loads                        */
/* ------------------------------------------------------------------------- */

static void nft_fullcone_build_range(const struct nft_fullcone *priv,
				     const struct nft_regs *regs,
				     u8 family, struct fc_range *out)
{
	memset(out, 0, sizeof(*out));
	out->flags  = priv->flags;
	out->family = family;

	if (priv->sreg_proto_min) {
		out->min_port = (__force __be16)
			nft_reg_load16(&regs->data[priv->sreg_proto_min]);
		out->max_port = (__force __be16)
			nft_reg_load16(&regs->data[priv->sreg_proto_max]);
	}

	if (priv->sreg_addr_min) {
		if (family == NFPROTO_IPV6) {
			memcpy(&out->min_addr.in6,
			       &regs->data[priv->sreg_addr_min],
			       sizeof(struct in6_addr));
			memcpy(&out->max_addr.in6,
			       &regs->data[priv->sreg_addr_max],
			       sizeof(struct in6_addr));
		} else {
			out->min_addr.ip = (__force __be32)
				nft_reg_load32(&regs->data[priv->sreg_addr_min]);
			out->max_addr.ip = (__force __be32)
				nft_reg_load32(&regs->data[priv->sreg_addr_max]);
		}
	}
}

/* ------------------------------------------------------------------------- */
/* IPv4 expression                                                            */
/* ------------------------------------------------------------------------- */

static void nft_fullcone_ipv4_eval(const struct nft_expr *expr,
				   struct nft_regs *regs,
				   const struct nft_pktinfo *pkt)
{
	const struct nft_fullcone *priv = nft_expr_priv(expr);
	struct fc_range range;

	nft_fullcone_build_range(priv, regs, NFPROTO_IPV4, &range);
	regs->verdict.code = fc_engine_eval(pkt->skb, nft_hook(pkt),
					    nft_out(pkt), &range);
}

static struct nft_expr_type nft_fullcone_ipv4_type;
static const struct nft_expr_ops nft_fullcone_ipv4_ops = {
	.type     = &nft_fullcone_ipv4_type,
	.size     = NFT_EXPR_SIZE(sizeof(struct nft_fullcone)),
	.eval     = nft_fullcone_ipv4_eval,
	.init     = nft_fullcone_common_init,
	.destroy  = nft_fullcone_common_destroy,
	.dump     = nft_fullcone_dump,
	.validate = nft_fullcone_validate,
};

static struct nft_expr_type nft_fullcone_ipv4_type __read_mostly = {
	.family   = NFPROTO_IPV4,
	.name     = "fullcone",
	.ops      = &nft_fullcone_ipv4_ops,
	.policy   = nft_fullcone_policy,
	.maxattr  = NFTA_FULLCONE_MAX,
	.owner    = THIS_MODULE,
};

/* ------------------------------------------------------------------------- */
/* IPv6 expression                                                            */
/* ------------------------------------------------------------------------- */

#ifdef CONFIG_NF_TABLES_IPV6
static void nft_fullcone_ipv6_eval(const struct nft_expr *expr,
				   struct nft_regs *regs,
				   const struct nft_pktinfo *pkt)
{
	const struct nft_fullcone *priv = nft_expr_priv(expr);
	struct fc_range range;

	nft_fullcone_build_range(priv, regs, NFPROTO_IPV6, &range);
	regs->verdict.code = fc_engine_eval(pkt->skb, nft_hook(pkt),
					    nft_out(pkt), &range);
}

static struct nft_expr_type nft_fullcone_ipv6_type;
static const struct nft_expr_ops nft_fullcone_ipv6_ops = {
	.type     = &nft_fullcone_ipv6_type,
	.size     = NFT_EXPR_SIZE(sizeof(struct nft_fullcone)),
	.eval     = nft_fullcone_ipv6_eval,
	.init     = nft_fullcone_common_init,
	.destroy  = nft_fullcone_common_destroy,
	.dump     = nft_fullcone_dump,
	.validate = nft_fullcone_validate,
};

static struct nft_expr_type nft_fullcone_ipv6_type __read_mostly = {
	.family   = NFPROTO_IPV6,
	.name     = "fullcone",
	.ops      = &nft_fullcone_ipv6_ops,
	.policy   = nft_fullcone_policy,
	.maxattr  = NFTA_FULLCONE_MAX,
	.owner    = THIS_MODULE,
};
#endif /* CONFIG_NF_TABLES_IPV6 */

/* ------------------------------------------------------------------------- */
/* inet (mixed family) expression                                            */
/* ------------------------------------------------------------------------- */

#ifdef CONFIG_NF_TABLES_INET
static void nft_fullcone_inet_eval(const struct nft_expr *expr,
				   struct nft_regs *regs,
				   const struct nft_pktinfo *pkt)
{
	switch (nft_pf(pkt)) {
	case NFPROTO_IPV4:
		nft_fullcone_ipv4_eval(expr, regs, pkt);
		return;
#ifdef CONFIG_NF_TABLES_IPV6
	case NFPROTO_IPV6:
		nft_fullcone_ipv6_eval(expr, regs, pkt);
		return;
#endif
	}
	WARN_ON_ONCE(1);
}

static struct nft_expr_type nft_fullcone_inet_type;
static const struct nft_expr_ops nft_fullcone_inet_ops = {
	.type     = &nft_fullcone_inet_type,
	.size     = NFT_EXPR_SIZE(sizeof(struct nft_fullcone)),
	.eval     = nft_fullcone_inet_eval,
	.init     = nft_fullcone_common_init,
	.destroy  = nft_fullcone_common_destroy,
	.dump     = nft_fullcone_dump,
	.validate = nft_fullcone_validate,
};

static struct nft_expr_type nft_fullcone_inet_type __read_mostly = {
	.family   = NFPROTO_INET,
	.name     = "fullcone",
	.ops      = &nft_fullcone_inet_ops,
	.policy   = nft_fullcone_policy,
	.maxattr  = NFTA_FULLCONE_MAX,
	.owner    = THIS_MODULE,
};
#endif /* CONFIG_NF_TABLES_INET */

/* ------------------------------------------------------------------------- */
/* Module init / exit                                                         */
/* ------------------------------------------------------------------------- */

static int __init nft_fullcone_init(void)
{
	int err;

	err = fc_engine_init();
	if (err)
		return err;

	err = nft_register_expr(&nft_fullcone_ipv4_type);
	if (err) {
		fc_engine_exit();
		return err;
	}

#ifdef CONFIG_NF_TABLES_IPV6
	err = nft_register_expr(&nft_fullcone_ipv6_type);
	if (err) {
		nft_unregister_expr(&nft_fullcone_ipv4_type);
		fc_engine_exit();
		return err;
	}
#endif

#ifdef CONFIG_NF_TABLES_INET
	err = nft_register_expr(&nft_fullcone_inet_type);
	if (err) {
#ifdef CONFIG_NF_TABLES_IPV6
		nft_unregister_expr(&nft_fullcone_ipv6_type);
#endif
		nft_unregister_expr(&nft_fullcone_ipv4_type);
		fc_engine_exit();
		return err;
	}
#endif

	return 0;
}

static void __exit nft_fullcone_exit(void)
{
#ifdef CONFIG_NF_TABLES_INET
	nft_unregister_expr(&nft_fullcone_inet_type);
#endif
#ifdef CONFIG_NF_TABLES_IPV6
	nft_unregister_expr(&nft_fullcone_ipv6_type);
#endif
	nft_unregister_expr(&nft_fullcone_ipv4_type);
	fc_engine_exit();
}

module_init(nft_fullcone_init);
module_exit(nft_fullcone_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Unified fullcone NAT (nftables expression)");
MODULE_AUTHOR("turboacc");
MODULE_ALIAS_NFT_EXPR("fullcone");
