// SPDX-License-Identifier: GPL-2.0-only
/*
 * Unified Full Cone NAT - Core Logic
 *
 * Port mapping is stored entirely in conntrack expectations.
 * No custom hash tables — all state is per-net by design.
 *
 * Based on the Broadcom fullcone NAT approach, extended to support
 * IPv4/IPv6 and UDP/TCP.
 */

#include "fullcone.h"

#include <linux/inetdevice.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <net/addrconf.h>
#include <net/ip6_route.h>
#include <net/netfilter/nf_nat.h>

/* RFC 4787 Section 4.2.2: Port Parity preservation */
#define CHECK_PORT_PARITY(a, b) (((a) & 1) == ((b) & 1))

/* Forward declarations */
static void fullcone_expect(struct nf_conn *ct,
			    struct nf_conntrack_expect *exp);
static int fullcone_help(struct sk_buff *skb, unsigned int protoff,
			 struct nf_conn *ct, enum ip_conntrack_info ctinfo);

/*
 * Expect policy shared by all four helpers.
 */
static struct nf_conntrack_expect_policy fullcone_exp_policy = {
	.max_expected	= FULLCONE_MAX_EXPECTED,
	.timeout	= FULLCONE_EXPECT_TIMEOUT,
};

/*
 * Four conntrack helpers: one per (family, protocol) combination.
 * The helper .help callback creates permanent expectations after SNAT.
 */
struct nf_conntrack_helper fullcone_helpers[FULLCONE_HELPER_MAX] = {
	[FULLCONE_HELPER_UDP4] = {
		.name			= "FULLCONE-UDP4",
		.me			= THIS_MODULE,
		.tuple.src.l3num	= AF_INET,
		.tuple.dst.protonum	= IPPROTO_UDP,
		.expect_policy		= &fullcone_exp_policy,
		.expect_class_max	= 1,
		.help			= fullcone_help,
	},
	[FULLCONE_HELPER_UDP6] = {
		.name			= "FULLCONE-UDP6",
		.me			= THIS_MODULE,
		.tuple.src.l3num	= AF_INET6,
		.tuple.dst.protonum	= IPPROTO_UDP,
		.expect_policy		= &fullcone_exp_policy,
		.expect_class_max	= 1,
		.help			= fullcone_help,
	},
	[FULLCONE_HELPER_TCP4] = {
		.name			= "FULLCONE-TCP4",
		.me			= THIS_MODULE,
		.tuple.src.l3num	= AF_INET,
		.tuple.dst.protonum	= IPPROTO_TCP,
		.expect_policy		= &fullcone_exp_policy,
		.expect_class_max	= 1,
		.help			= fullcone_help,
	},
	[FULLCONE_HELPER_TCP6] = {
		.name			= "FULLCONE-TCP6",
		.me			= THIS_MODULE,
		.tuple.src.l3num	= AF_INET6,
		.tuple.dst.protonum	= IPPROTO_TCP,
		.expect_policy		= &fullcone_exp_policy,
		.expect_class_max	= 1,
		.help			= fullcone_help,
	},
};
EXPORT_SYMBOL_GPL(fullcone_helpers);

/*
 * Check if a conntrack helper is one of ours.
 */
static inline bool is_our_helper(const struct nf_conntrack_helper *helper)
{
	int i;

	if (!helper)
		return false;
	for (i = 0; i < FULLCONE_HELPER_MAX; i++) {
		if (helper == &fullcone_helpers[i])
			return true;
	}
	return false;
}

/*
 * Select the appropriate helper for a given family and protocol.
 */
static struct nf_conntrack_helper *
fullcone_select_helper(sa_family_t family, u8 proto)
{
	if (family == AF_INET) {
		if (proto == IPPROTO_UDP)
			return &fullcone_helpers[FULLCONE_HELPER_UDP4];
		if (proto == IPPROTO_TCP)
			return &fullcone_helpers[FULLCONE_HELPER_TCP4];
	} else if (family == AF_INET6) {
		if (proto == IPPROTO_UDP)
			return &fullcone_helpers[FULLCONE_HELPER_UDP6];
		if (proto == IPPROTO_TCP)
			return &fullcone_helpers[FULLCONE_HELPER_TCP6];
	}
	return NULL;
}

/*
 * Get the primary address of an outbound device.
 * For IPv4: first address on the interface.
 * For IPv6: first global-scope non-tentative address.
 */
static int fullcone_get_device_addr(const struct net_device *dev,
				    sa_family_t family,
				    union nf_inet_addr *addr)
{
	if (family == AF_INET) {
		const struct in_device *in_dev;

		rcu_read_lock();
		in_dev = __in_dev_get_rcu(dev);
		if (in_dev && in_dev->ifa_list) {
			addr->ip = in_dev->ifa_list->ifa_local;
			rcu_read_unlock();
			return 0;
		}
		rcu_read_unlock();
		return -ENOENT;
	} else if (family == AF_INET6) {
		struct inet6_dev *in6_dev;
		struct inet6_ifaddr *ifa;

		rcu_read_lock();
		in6_dev = __in6_dev_get(dev);
		if (!in6_dev) {
			rcu_read_unlock();
			return -ENOENT;
		}
		list_for_each_entry_rcu(ifa, &in6_dev->addr_list, if_list) {
			if (ifa->scope == RT_SCOPE_UNIVERSE &&
			    !(ifa->flags & IFA_F_TENTATIVE)) {
				addr->in6 = ifa->addr;
				rcu_read_unlock();
				return 0;
			}
		}
		rcu_read_unlock();
		return -ENOENT;
	}
	return -EINVAL;
}

/*
 * Check if a port is already in use by an existing expectation.
 * Uses __nf_ct_expect_find() for O(1) hash lookup.
 */
static bool fullcone_port_in_use(struct net *net,
				 const struct nf_conntrack_zone *zone,
				 sa_family_t family, u8 proto,
				 const union nf_inet_addr *wan_addr,
				 __be16 port)
{
	struct nf_conntrack_tuple tuple;
	struct nf_conntrack_expect *exp;

	memset(&tuple, 0, sizeof(tuple));
	tuple.src.l3num = family;
	tuple.dst.protonum = proto;
	tuple.dst.u3 = *wan_addr;
	tuple.dst.u.all = port;

	rcu_read_lock();
	exp = __nf_ct_expect_find(net, zone, &tuple);
	rcu_read_unlock();

	return exp != NULL;
}

/*
 * Find an existing fullcone expectation for a given internal endpoint.
 * Walks the entire expect hash table — O(n) but only called for new connections.
 *
 * Matches expectations where:
 *   - saved_addr == internal IP (the original source we need to restore)
 *   - saved_proto == internal port
 *   - tuple.src is wildcarded (fullcone: any source can reach us)
 *   - family and protocol match
 */
static struct nf_conntrack_expect *
fullcone_find_existing_mapping(struct net *net,
			       sa_family_t family, u8 proto,
			       const union nf_inet_addr *int_addr,
			       __be16 int_port)
{
	struct nf_conntrack_expect *exp;
	unsigned int h;

	rcu_read_lock();
	for (h = 0; h < nf_ct_expect_hsize; h++) {
		hlist_for_each_entry_rcu(exp, &nf_ct_expect_hash[h], hnode) {
			if (exp->tuple.src.l3num != family)
				continue;
			if (exp->tuple.dst.protonum != proto)
				continue;
			if (!nf_inet_addr_cmp(&exp->saved_addr, int_addr))
				continue;
			if (exp->saved_proto.all != int_port)
				continue;
			/* Verify wildcard source (fullcone signature) */
			if (exp->tuple.src.u.all != 0)
				continue;
			rcu_read_unlock();
			return exp;
		}
	}
	rcu_read_unlock();
	return NULL;
}

/*
 * Allocate an external port for a new fullcone mapping.
 *
 * 1. Check for an existing mapping for this internal endpoint → reuse port.
 * 2. Try the original source port (port preservation).
 * 3. Linear scan with RFC 4787 port parity preservation.
 */
static __be16 fullcone_alloc_port(struct net *net,
				  const struct nf_conntrack_zone *zone,
				  sa_family_t family, u8 proto,
				  const union nf_inet_addr *wan_addr,
				  const union nf_inet_addr *int_addr,
				  __be16 int_port)
{
	struct nf_conntrack_expect *existing;
	u16 orig_port, port, parity;

	/* Reuse existing mapping if present */
	existing = fullcone_find_existing_mapping(net, family, proto,
						  int_addr, int_port);
	if (existing)
		return existing->tuple.dst.u.all;

	orig_port = ntohs(int_port);
	if (orig_port < FULLCONE_PORT_MIN)
		orig_port = FULLCONE_PORT_MIN;
	parity = orig_port & 1;

	/* Try original port first */
	if (!fullcone_port_in_use(net, zone, family, proto,
				  wan_addr, htons(orig_port)))
		return htons(orig_port);

	/* Linear scan with parity preservation */
	for (port = FULLCONE_PORT_MIN + parity;
	     port <= FULLCONE_PORT_MAX; port += 2) {
		if (port == orig_port)
			continue;
		if (!fullcone_port_in_use(net, zone, family, proto,
					  wan_addr, htons(port)))
			return htons(port);
	}

	/* Try opposite parity as last resort */
	for (port = FULLCONE_PORT_MIN + (1 - parity);
	     port <= FULLCONE_PORT_MAX; port += 2) {
		if (!fullcone_port_in_use(net, zone, family, proto,
					  wan_addr, htons(port)))
			return htons(port);
	}

	return 0; /* no port available */
}

/*
 * Expectation callback: applied to new inbound connections matching
 * a fullcone expectation. Performs DNAT to the internal host.
 */
static void fullcone_expect(struct nf_conn *ct,
			    struct nf_conntrack_expect *exp)
{
	struct nf_nat_range2 range;

	BUG_ON(ct->status & IPS_NAT_DONE_MASK);

	/* SRC: keep the external sender's address unchanged */
	memset(&range, 0, sizeof(range));
	range.flags = NF_NAT_RANGE_MAP_IPS;
	range.min_addr = range.max_addr =
		ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3;
	nf_nat_setup_info(ct, &range, NF_NAT_MANIP_SRC);

	/* DST: rewrite to internal host:port from saved expectation */
	memset(&range, 0, sizeof(range));
	range.flags = NF_NAT_RANGE_MAP_IPS | NF_NAT_RANGE_PROTO_SPECIFIED;
	range.min_proto = range.max_proto = exp->saved_proto;
	range.min_addr = range.max_addr = exp->saved_addr;
	nf_nat_setup_info(ct, &range, NF_NAT_MANIP_DST);
}

/*
 * Conntrack helper callback: called for each packet on a fullcone-managed
 * connection. Creates a permanent expectation after the first outbound packet
 * (UDP) or after TCP establishment.
 */
static int fullcone_help(struct sk_buff *skb, unsigned int protoff,
			 struct nf_conn *ct, enum ip_conntrack_info ctinfo)
{
	int dir = CTINFO2DIR(ctinfo);
	struct nf_conn_help *help = nfct_help(ct);
	struct nf_conntrack_expect *exp;
	sa_family_t family = nf_ct_l3num(ct);
	u8 proto = nf_ct_protonum(ct);

	/* Only process original direction */
	if (dir != IP_CT_DIR_ORIGINAL)
		return NF_ACCEPT;

	/* Already have an expectation? */
	if (help->expecting[NF_CT_EXPECT_CLASS_DEFAULT])
		return NF_ACCEPT;

	/* For TCP: wait until connection is established */
	if (proto == IPPROTO_TCP) {
		if (ct->proto.tcp.state < TCP_CONNTRACK_ESTABLISHED)
			return NF_ACCEPT;
	}

	exp = nf_ct_expect_alloc(ct);
	if (!exp) {
		pr_err("fullcone: failed to allocate expectation\n");
		return NF_ACCEPT;
	}

	/*
	 * Create expectation:
	 *   - Source: wildcard (any external host can reach us — full cone)
	 *   - Destination: WAN IP + mapped port (from reply tuple)
	 *   - Protocol: same as connection
	 */
	nf_ct_expect_init(exp, NF_CT_EXPECT_CLASS_DEFAULT, family,
			  NULL, /* any source address */
			  &ct->tuplehash[!dir].tuple.dst.u3,
			  proto,
			  NULL, /* any source port */
			  &ct->tuplehash[!dir].tuple.dst.u.all);

	exp->flags = NF_CT_EXPECT_PERMANENT;
	exp->saved_addr = ct->tuplehash[dir].tuple.src.u3;
	exp->saved_proto.all = ct->tuplehash[dir].tuple.src.u.all;
	exp->dir = !dir;
	exp->expectfn = fullcone_expect;

	nf_ct_expect_related(exp, 0);
	nf_ct_expect_put(exp);

	pr_debug("fullcone: expectation created for %pI4:%u (family=%d proto=%d)\n",
		 &ct->tuplehash[!dir].tuple.dst.u3.ip,
		 ntohs(ct->tuplehash[!dir].tuple.dst.u.udp.port),
		 family, proto);

	return NF_ACCEPT;
}

/*
 * POSTROUTING handler: called by both xt and nft frontends.
 * Allocates a port, applies SNAT, and attaches the conntrack helper.
 */
unsigned int fullcone_do_postrouting(struct sk_buff *skb,
				     const struct net_device *out,
				     sa_family_t family)
{
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;
	struct nf_conn_help *help;
	struct nf_conntrack_helper *helper;
	struct nf_nat_range2 range;
	union nf_inet_addr wan_addr;
	__be16 mapped_port;
	u8 proto;
	int ret;

	ct = nf_ct_get(skb, &ctinfo);
	if (!ct || ctinfo == IP_CT_RELATED_REPLY)
		return NF_ACCEPT;

	/* Only handle original direction new/established packets */
	if (CTINFO2DIR(ctinfo) != IP_CT_DIR_ORIGINAL)
		return NF_ACCEPT;

	/* Already managed by our helper? */
	help = nfct_help(ct);
	if (help && is_our_helper(help->helper))
		return NF_ACCEPT;

	/* Only handle UDP and TCP */
	proto = nf_ct_protonum(ct);
	if (proto != IPPROTO_UDP && proto != IPPROTO_TCP)
		return NF_ACCEPT;

	/* Get WAN address from outbound device */
	if (fullcone_get_device_addr(out, family, &wan_addr) < 0)
		return NF_DROP;

	/* Allocate external port */
	mapped_port = fullcone_alloc_port(
		nf_ct_net(ct), nf_ct_zone(ct), family, proto,
		&wan_addr,
		&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3,
		ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all);

	if (!mapped_port) {
		pr_warn_ratelimited("fullcone: port exhaustion\n");
		return NF_DROP;
	}

	/* Apply SNAT */
	memset(&range, 0, sizeof(range));
	range.flags = NF_NAT_RANGE_MAP_IPS | NF_NAT_RANGE_PROTO_SPECIFIED;
	range.min_addr = range.max_addr = wan_addr;
	range.min_proto.all = range.max_proto.all = mapped_port;

	ret = nf_nat_setup_info(ct, &range, NF_NAT_MANIP_SRC);
	if (ret != NF_ACCEPT)
		return ret;

	/* Attach our conntrack helper */
	helper = fullcone_select_helper(family, proto);
	if (!helper)
		return NF_ACCEPT;

	help = nfct_help(ct);
	if (!help)
		help = nf_ct_helper_ext_add(ct, GFP_ATOMIC);
	if (help) {
		help->helper = helper;
		pr_debug("fullcone: helper %s attached\n", helper->name);
	}

	return NF_ACCEPT;
}

/*
 * PREROUTING handler.
 * Expectations handle inbound DNAT automatically inside conntrack.
 * This hook exists only because nftables requires the expression
 * to be valid in prerouting chains.
 */
unsigned int fullcone_do_prerouting(struct sk_buff *skb,
				    sa_family_t family)
{
	return NF_ACCEPT;
}

/*
 * Register all conntrack helpers.
 */
int fullcone_core_init(void)
{
	int i, ret;

	for (i = 0; i < FULLCONE_HELPER_MAX; i++) {
		ret = nf_conntrack_helper_register(&fullcone_helpers[i]);
		if (ret) {
			pr_err("fullcone: failed to register helper %s: %d\n",
			       fullcone_helpers[i].name, ret);
			while (--i >= 0)
				nf_conntrack_helper_unregister(
					&fullcone_helpers[i]);
			return ret;
		}
	}

	pr_info("fullcone: %d conntrack helpers registered\n",
		FULLCONE_HELPER_MAX);
	return 0;
}

/*
 * Unregister all conntrack helpers.
 * This also cleans up any expectations created by these helpers.
 */
void fullcone_core_exit(void)
{
	int i;

	for (i = FULLCONE_HELPER_MAX - 1; i >= 0; i--)
		nf_conntrack_helper_unregister(&fullcone_helpers[i]);

	pr_info("fullcone: conntrack helpers unregistered\n");
}
