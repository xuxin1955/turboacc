// SPDX-License-Identifier: GPL-2.0-only
/*
 * Unified Full Cone NAT - nftables expression integration
 *
 * Registers "fullcone" nft expression compatible with existing
 * libnftnl and nftables userspace patches.
 *
 * Netlink attributes: NFTA_FULLCONE_{FLAGS, REG_PROTO_MIN, REG_PROTO_MAX}
 * (defined in patched nf_tables.h via libnftnl patch).
 */

#include "fullcone.h"

#include <net/netfilter/nf_tables.h>

/*
 * Netlink attribute enum — must match the libnftnl patch definitions.
 * Defined here locally to avoid dependency on patched kernel headers
 * at build time.
 */
enum nft_fullcone_attributes {
	NFTA_FULLCONE_UNSPEC,
	NFTA_FULLCONE_FLAGS,
	NFTA_FULLCONE_REG_PROTO_MIN,
	NFTA_FULLCONE_REG_PROTO_MAX,
	__NFTA_FULLCONE_MAX
};
#define NFTA_FULLCONE_MAX (__NFTA_FULLCONE_MAX - 1)

struct nft_fullcone {
	u32	flags;
	u8	sreg_proto_min;
	u8	sreg_proto_max;
};

static const struct nla_policy
nft_fullcone_policy[NFTA_FULLCONE_MAX + 1] = {
	[NFTA_FULLCONE_FLAGS]		= { .type = NLA_U32 },
	[NFTA_FULLCONE_REG_PROTO_MIN]	= { .type = NLA_U32 },
	[NFTA_FULLCONE_REG_PROTO_MAX]	= { .type = NLA_U32 },
};

static void nft_fullcone_eval(const struct nft_expr *expr,
			      struct nft_regs *regs,
			      const struct nft_pktinfo *pkt)
{
	sa_family_t family = nft_pf(pkt);
	unsigned int hooknum = nft_hook(pkt);

	if (hooknum == NF_INET_POST_ROUTING)
		regs->verdict.code =
			fullcone_do_postrouting(pkt->skb, nft_out(pkt), family);
	else if (hooknum == NF_INET_PRE_ROUTING)
		regs->verdict.code =
			fullcone_do_prerouting(pkt->skb, family);
}

/*
 * nft_fullcone_validate() — kernel version compatibility.
 *
 * The function signature changed between kernel versions:
 *   6.6.113+ and 6.12+: 2 parameters (ctx, expr)
 *   Earlier 6.6.x and 6.11.x: 3 parameters (ctx, expr, data)
 */
#if ((LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 113)) && \
     (LINUX_VERSION_CODE <  KERNEL_VERSION(6, 7, 0))) || \
     (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0))
static int nft_fullcone_validate(const struct nft_ctx *ctx,
				 const struct nft_expr *expr)
#else
static int nft_fullcone_validate(const struct nft_ctx *ctx,
				 const struct nft_expr *expr,
				 const struct nft_data **data)
#endif
{
	return nft_chain_validate_hooks(ctx->chain,
		(1 << NF_INET_PRE_ROUTING) | (1 << NF_INET_POST_ROUTING));
}

static int nft_fullcone_init(const struct nft_ctx *ctx,
			     const struct nft_expr *expr,
			     const struct nlattr * const tb[])
{
	struct nft_fullcone *priv = nft_expr_priv(expr);

	if (tb[NFTA_FULLCONE_FLAGS])
		priv->flags = ntohl(nla_get_be32(tb[NFTA_FULLCONE_FLAGS]));

	return nf_ct_netns_get(ctx->net, ctx->family);
}

static void nft_fullcone_destroy(const struct nft_ctx *ctx,
				 const struct nft_expr *expr)
{
	nf_ct_netns_put(ctx->net, ctx->family);
}

static int nft_fullcone_dump(struct sk_buff *skb,
			     const struct nft_expr *expr, bool reset)
{
	const struct nft_fullcone *priv = nft_expr_priv(expr);

	if (priv->flags &&
	    nla_put_be32(skb, NFTA_FULLCONE_FLAGS, htonl(priv->flags)))
		goto nla_put_failure;

	return 0;

nla_put_failure:
	return -1;
}

static struct nft_expr_type nft_fullcone_type;

static const struct nft_expr_ops nft_fullcone_ipv4_ops = {
	.type		= &nft_fullcone_type,
	.size		= NFT_EXPR_SIZE(sizeof(struct nft_fullcone)),
	.eval		= nft_fullcone_eval,
	.init		= nft_fullcone_init,
	.destroy	= nft_fullcone_destroy,
	.dump		= nft_fullcone_dump,
	.validate	= nft_fullcone_validate,
};

static const struct nft_expr_ops nft_fullcone_ipv6_ops = {
	.type		= &nft_fullcone_type,
	.size		= NFT_EXPR_SIZE(sizeof(struct nft_fullcone)),
	.eval		= nft_fullcone_eval,
	.init		= nft_fullcone_init,
	.destroy	= nft_fullcone_destroy,
	.dump		= nft_fullcone_dump,
	.validate	= nft_fullcone_validate,
};

static const struct nft_expr_ops *
nft_fullcone_select_ops(const struct nft_ctx *ctx,
			const struct nlattr * const tb[])
{
	switch (ctx->family) {
	case NFPROTO_IPV4:
		return &nft_fullcone_ipv4_ops;
	case NFPROTO_IPV6:
		return &nft_fullcone_ipv6_ops;
	case NFPROTO_INET:
		/* INET family: eval callback uses nft_pf() at runtime */
		return &nft_fullcone_ipv4_ops;
	default:
		return ERR_PTR(-EOPNOTSUPP);
	}
}

static struct nft_expr_type nft_fullcone_type __read_mostly = {
	.name		= "fullcone",
	.select_ops	= nft_fullcone_select_ops,
	.policy		= nft_fullcone_policy,
	.maxattr	= NFTA_FULLCONE_MAX,
	.flags		= NFT_EXPR_STATEFUL,
	.owner		= THIS_MODULE,
};

int fullcone_nft_init(void)
{
	return nft_register_expr(&nft_fullcone_type);
}

void fullcone_nft_exit(void)
{
	nft_unregister_expr(&nft_fullcone_type);
}
