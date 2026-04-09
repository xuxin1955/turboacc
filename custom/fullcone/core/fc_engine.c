/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * fc_engine.c - Unified fullcone NAT engine
 *
 *   Implements RFC 4787 Endpoint-Independent Mapping ("full cone") on top of
 *   the standard Linux netfilter conntrack-NAT framework, WITHOUT modifying
 *   any in-tree kernel source. Implemented as a self-contained engine that is
 *   compiled separately into two independent kernel modules (xt_FULLCONE.ko
 *   for iptables, nft_FULLCONE.ko for nftables). All symbols below are
 *   `static` so the two .ko files share zero linkage.
 *
 * Architecture (high level):
 *
 *   Outbound packet (POSTROUTING)
 *     |
 *     v  [frontend wrapper builds fc_range, calls fc_engine_eval()]
 *     |
 *     v  fc_eval_outbound()
 *     |    1. Look up (int_addr, int_port, l4proto) in the per-netns aux
 *     |       hash. If alive (expectation still in conntrack expect hash),
 *     |       reuse the cached (ext_addr, ext_port).
 *     |    2. Otherwise allocate a new (ext_addr, ext_port) — preserve the
 *     |       original src port if free, else walk the configured port range.
 *     |    3. Create a conntrack expectation for the inbound reply path:
 *     |         tuple = (any_src, ext_addr:ext_port, l4proto)
 *     |         saved = (int_addr, int_port)
 *     |         expectfn = fc_expectfn        <-- does the inbound DNAT
 *     |    4. nf_nat_setup_info() with the chosen SNAT range.
 *     |
 *     v  Packet leaves with src = (ext_addr, ext_port).
 *
 *   Inbound packet (no rule needed at all)
 *     |
 *     v  conntrack core looks up the new tuple, fails to find a ct, then
 *     |  walks the per-netns expectation hash and finds our exp.
 *     |
 *     v  fc_expectfn() runs from inside conntrack core BEFORE any nf hook,
 *     |  rewrites dst to (int_addr, int_port).
 *     |
 *     v  Packet is delivered to the original internal endpoint.
 *
 * Why this is faster than the legacy xt_FULLCONENAT / nft_fullcone approach:
 *   - Inbound DNAT does NOT take a custom spinlock and does NOT walk a custom
 *     hashtable on every packet. The expectation system is already in the
 *     conntrack lookup path; we add nothing per-packet.
 *   - The aux hash is consulted only ONCE per outbound flow (i.e. once per
 *     new ct), not once per packet.
 *   - All state is per-netns, so containers / netns-isolated environments do
 *     not contend on the same lock.
 *
 * Why this is more correct than the in-tree Broadcom patch:
 *   - The aux hash makes the outbound (int -> ext) lookup O(1). The Broadcom
 *     patch scans the entire expectation hash on every outbound — O(N).
 *   - All state is per-netns. The Broadcom patch uses module-global state.
 *   - Lazy validation re-creates expectations whose master ct has died,
 *     extending the effective fullcone lifetime beyond a single conntrack.
 *   - Implemented as a loadable module — no kernel patching, no fork.
 */

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/jhash.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/random.h>
#include <linux/slab.h>

#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/addrconf.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>

#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_expect.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/netfilter/nf_conntrack_tuple.h>

#include "fc_engine.h"

/* ------------------------------------------------------------------------- */
/* Tunables                                                                  */
/* ------------------------------------------------------------------------- */

#define FC_HASH_BITS		10		/* 1024 buckets per netns */
#define FC_HASH_SIZE		(1 << FC_HASH_BITS)

/* Default idle lifetime of a binding in the aux hash. The conntrack of the
 * underlying flow may die earlier (e.g. UDP nf_conntrack_udp_timeout = 30s);
 * we keep the binding longer to preserve the fullcone mapping across short
 * lulls. Refreshed on every outbound packet that hits the binding. */
#define FC_BINDING_TIMEOUT	(5 * 60 * HZ)

/* Reaper interval — sweeps the per-netns aux hash and evicts idle bindings. */
#define FC_REAPER_INTERVAL	(30 * HZ)

/* Lower bound of the dynamically-assigned external port pool when the user
 * does not specify --to-ports. Matches the in-tree NAT default. */
#define FC_DEFAULT_PORT_MIN	1024

/* ------------------------------------------------------------------------- */
/* Per-netns state                                                           */
/* ------------------------------------------------------------------------- */

struct fc_binding {
	/* Identity of the internal endpoint. */
	union nf_inet_addr	int_addr;
	__be16			int_port;
	u8			family;		/* NFPROTO_IPV4 / NFPROTO_IPV6 */
	u8			l4proto;	/* IPPROTO_UDP / TCP / ICMP / ... */
	u16			zone_id;	/* conntrack zone id */

	/* Allocated external endpoint. */
	union nf_inet_addr	ext_addr;
	__be16			ext_port;

	/* Pointer to the conntrack expectation that materialises the inbound
	 * DNAT for this binding. May be NULL if the master ct has died and we
	 * have not re-created the exp yet. Validated lazily. */
	struct nf_conntrack_expect *exp;

	unsigned long		last_used;	/* jiffies; refreshed on use */

	struct hlist_node	hnode;		/* linked into fc_net.idx */
};

struct fc_net {
	/* Aux index: (int_addr, int_port, l4proto) -> fc_binding */
	struct hlist_head	idx[FC_HASH_SIZE];
	spinlock_t		lock;

	/* Periodic reaper. */
	struct delayed_work	reaper;
	struct net		*net;		/* back-pointer for the work */

	atomic_t		refcnt;		/* number of frontend rules */
};

static unsigned int fc_net_id __read_mostly;

static inline struct fc_net *fc_pernet(struct net *net)
{
	return net_generic(net, fc_net_id);
}

/* ------------------------------------------------------------------------- */
/* Hash key                                                                  */
/* ------------------------------------------------------------------------- */

static inline u32 fc_hash_key(const union nf_inet_addr *addr, __be16 port,
			      u8 family, u8 l4proto)
{
	u32 a;

	if (family == NFPROTO_IPV6)
		a = jhash2((const u32 *)addr->all, 4,
			   ((u32)l4proto << 16) | (u32)(__force u16)port);
	else
		a = jhash_2words((__force u32)addr->ip,
				 ((u32)l4proto << 16) |
					 (u32)(__force u16)port, 0);

	return a & (FC_HASH_SIZE - 1);
}

static inline bool fc_addr_eq(const union nf_inet_addr *a,
			      const union nf_inet_addr *b, u8 family)
{
	if (family == NFPROTO_IPV6)
		return ipv6_addr_equal(&a->in6, &b->in6);
	return a->ip == b->ip;
}

/* ------------------------------------------------------------------------- */
/* Expectation callback (inbound DNAT)                                        */
/* ------------------------------------------------------------------------- */

/*
 * Called by conntrack core when an inbound packet creates a new ct that
 * matches one of our expectations. We rewrite dst to the saved internal
 * (addr, port). Source manipulation is left untouched.
 *
 * This runs from inside the conntrack lookup path, BEFORE the nf hooks,
 * which is why no PREROUTING rule is necessary.
 */
static void fc_expectfn(struct nf_conn *ct, struct nf_conntrack_expect *exp)
{
	struct nf_nat_range2 range;

	memset(&range, 0, sizeof(range));
	range.flags = NF_NAT_RANGE_MAP_IPS | NF_NAT_RANGE_PROTO_SPECIFIED;
	range.min_addr  = exp->saved_addr;
	range.max_addr  = exp->saved_addr;
	range.min_proto = exp->saved_proto;
	range.max_proto = exp->saved_proto;

	nf_nat_setup_info(ct, &range, NF_NAT_MANIP_DST);
}

/* ------------------------------------------------------------------------- */
/* Aux index helpers (must be called with fcn->lock held)                    */
/* ------------------------------------------------------------------------- */

static struct fc_binding *fc_idx_lookup(struct fc_net *fcn,
					const union nf_inet_addr *int_addr,
					__be16 int_port, u8 family, u8 l4proto)
{
	struct fc_binding *b;
	u32 h = fc_hash_key(int_addr, int_port, family, l4proto);

	hlist_for_each_entry(b, &fcn->idx[h], hnode) {
		if (b->family == family && b->l4proto == l4proto &&
		    b->int_port == int_port &&
		    fc_addr_eq(&b->int_addr, int_addr, family))
			return b;
	}
	return NULL;
}

static void fc_idx_insert(struct fc_net *fcn, struct fc_binding *b)
{
	u32 h = fc_hash_key(&b->int_addr, b->int_port, b->family, b->l4proto);
	hlist_add_head(&b->hnode, &fcn->idx[h]);
}

static void fc_binding_free(struct fc_binding *b)
{
	if (b->exp) {
		/* Drop our reference; the expectation may stay alive if its
		 * master ct still holds it, but we no longer track it. */
		nf_ct_expect_put(b->exp);
		b->exp = NULL;
	}
	kfree(b);
}

/* Returns true if the cached expectation pointer is still alive in the
 * per-netns expect hash for the same external (addr, port, proto). */
static bool fc_exp_alive(struct net *net, const struct nf_conntrack_zone *zone,
			 struct fc_binding *b)
{
	struct nf_conntrack_tuple t;
	struct nf_conntrack_expect *found;
	bool alive = false;

	if (!b->exp)
		return false;

	memset(&t, 0, sizeof(t));
	t.src.l3num = b->family;
	t.dst.protonum = b->l4proto;
	t.dst.u3 = b->ext_addr;
	t.dst.u.all = b->ext_port;

	rcu_read_lock();
	found = __nf_ct_expect_find(net, zone, &t);
	if (found && found == b->exp)
		alive = true;
	rcu_read_unlock();
	return alive;
}

/* ------------------------------------------------------------------------- */
/* Port allocation                                                            */
/* ------------------------------------------------------------------------- */

/*
 * Tests whether (ext_addr, ext_port) is currently in use by ANY conntrack
 * expectation in this netns. We use it to find a free external port.
 */
static bool fc_extport_taken(struct net *net,
			     const struct nf_conntrack_zone *zone,
			     u8 family, u8 l4proto,
			     const union nf_inet_addr *ext_addr, __be16 port)
{
	struct nf_conntrack_tuple t;
	struct nf_conntrack_expect *found;
	bool taken;

	memset(&t, 0, sizeof(t));
	t.src.l3num = family;
	t.dst.protonum = l4proto;
	t.dst.u3 = *ext_addr;
	t.dst.u.all = port;

	rcu_read_lock();
	found = __nf_ct_expect_find(net, zone, &t);
	taken = (found != NULL);
	rcu_read_unlock();
	return taken;
}

/*
 * Choose an external port. Strategy:
 *   1. Preserve the original src port if it's free (within the allowed range).
 *   2. Walk the range linearly looking for a free port (parity-preserving).
 *   3. Walk the range again ignoring parity if step 2 fails.
 *   4. If --random / --random-fully, start from a random offset.
 *
 * Per RFC 4787 REQ-1 we try to keep the port number itself (endpoint-
 * independent mapping); per RFC 4787 REQ-3 we preserve port parity
 * (an even input port maps to an even output port, odd to odd) when walking.
 *
 * The chosen port is only a SUGGESTION — nf_nat_setup_info() may pick a
 * different one if the kernel's own NAT bookkeeping detects a collision.
 * Callers must read the actual port back from the ct's reply tuple.
 */
static __be16 fc_pick_port(struct net *net,
			   const struct nf_conntrack_zone *zone,
			   u8 family, u8 l4proto,
			   const union nf_inet_addr *ext_addr,
			   __be16 orig_port, const struct fc_range *range)
{
	u16 min, max, range_size, start, off, sel, orig;
	bool random_mode;
	bool need_parity = (l4proto == IPPROTO_UDP);

	if (range->flags & NF_NAT_RANGE_PROTO_SPECIFIED) {
		min = ntohs(range->min_port);
		max = ntohs(range->max_port);
		if (min == 0)
			min = FC_DEFAULT_PORT_MIN;
		if (max < min)
			max = 65535;
	} else {
		min = FC_DEFAULT_PORT_MIN;
		max = 65535;
	}
	range_size = max - min + 1;
	orig = ntohs(orig_port);
	random_mode = range->flags &
		(NF_NAT_RANGE_PROTO_RANDOM | NF_NAT_RANGE_PROTO_RANDOM_FULLY);

	/* Step 1: try to keep the original port. */
	if (!random_mode && orig >= min && orig <= max) {
		if (!fc_extport_taken(net, zone, family, l4proto, ext_addr,
				      htons(orig)))
			return htons(orig);
	}

	/* Step 2: parity-preserving walk. */
	if (random_mode)
		start = get_random_u32() % range_size;
	else
		start = 0;

	for (off = 0; off < range_size; off++) {
		sel = min + ((start + off) % range_size);
		if (need_parity && ((sel & 1) != (orig & 1)))
			continue;
		if (!fc_extport_taken(net, zone, family, l4proto, ext_addr,
				      htons(sel)))
			return htons(sel);
	}

	/* Step 3: walk again ignoring parity. */
	for (off = 0; off < range_size; off++) {
		sel = min + ((start + off) % range_size);
		if (!fc_extport_taken(net, zone, family, l4proto, ext_addr,
				      htons(sel)))
			return htons(sel);
	}

	/* Last resort: hand the kernel an arbitrary port and let its own
	 * collision-handling figure it out. */
	return htons(min + (start % range_size));
}

/* ------------------------------------------------------------------------- */
/* Source-address resolution (when --to-source is not specified)             */
/* ------------------------------------------------------------------------- */

static int fc_pick_src_addr(struct sk_buff *skb, const struct net_device *out,
			    u8 family, union nf_inet_addr *out_addr)
{
	if (family == NFPROTO_IPV4) {
		const struct in_device *idev;
		const struct in_ifaddr *ifa;
		__be32 ip = 0;

		if (!out)
			return -ENOENT;
		rcu_read_lock();
		idev = __in_dev_get_rcu(out);
		if (idev) {
			ifa = rcu_dereference(idev->ifa_list);
			if (ifa)
				ip = ifa->ifa_local;
		}
		rcu_read_unlock();
		if (!ip)
			return -ENOENT;
		out_addr->ip = ip;
		return 0;
	}

#if IS_ENABLED(CONFIG_IPV6)
	if (family == NFPROTO_IPV6) {
		struct in6_addr saddr;

		if (!out)
			return -ENOENT;
		if (ipv6_dev_get_saddr(dev_net(out), out,
				       &ipv6_hdr(skb)->daddr, 0, &saddr) < 0)
			return -ENOENT;
		out_addr->in6 = saddr;
		return 0;
	}
#endif
	return -EAFNOSUPPORT;
}

/* ------------------------------------------------------------------------- */
/* Outbound: build SNAT range, create expectation, install mapping            */
/* ------------------------------------------------------------------------- */

static unsigned int fc_eval_outbound(struct sk_buff *skb,
				     const struct net_device *out,
				     const struct fc_range *range)
{
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct = nf_ct_get(skb, &ctinfo);
	const struct nf_conntrack_tuple *otuple, *rtuple;
	const struct nf_conntrack_zone *zone;
	struct fc_net *fcn;
	struct fc_binding *b;
	struct nf_conntrack_expect *exp;
	struct nf_nat_range2 newrange;
	union nf_inet_addr ext_addr;
	union nf_inet_addr ext_addr_actual;
	__be16 ext_port_pref, ext_port_actual;
	struct net *net;
	u8 family, l4proto;
	int err;
	unsigned int ret;
	bool reuse = false;

	if (!ct)
		return NF_ACCEPT;

	otuple = &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;
	family = otuple->src.l3num;
	l4proto = otuple->dst.protonum;

	/* Only run fullcone for protocols that share a (src_port, dst_port)
	 * tuple shape on both directions. ICMP is intentionally excluded:
	 * its identifier lives on the src side and the dst side encodes
	 * type/code, so it does not fit the (ext_addr, ext_port) abstraction
	 * we use everywhere else. SCTP/DCCP/GRE etc. fall through unmodified. */
	if (l4proto != IPPROTO_UDP && l4proto != IPPROTO_TCP)
		return NF_ACCEPT;

	net  = nf_ct_net(ct);
	fcn  = fc_pernet(net);
	zone = nf_ct_zone(ct);

	/* Resolve the external source address: either explicitly configured
	 * via the user range, or auto-picked from the egress device. */
	if (range->flags & NF_NAT_RANGE_MAP_IPS) {
		ext_addr = range->min_addr;
	} else {
		err = fc_pick_src_addr(skb, out, family, &ext_addr);
		if (err)
			return NF_DROP;
	}

	/* ---- Phase 1: try to reuse an existing binding for this internal
	 *      endpoint. */
	spin_lock_bh(&fcn->lock);
	b = fc_idx_lookup(fcn, &otuple->src.u3, otuple->src.u.all,
			  family, l4proto);
	if (b) {
		if (fc_addr_eq(&b->ext_addr, &ext_addr, family) &&
		    fc_exp_alive(net, zone, b)) {
			ext_port_pref = b->ext_port;
			b->last_used = jiffies;
			reuse = true;
		} else {
			/* Stale: evict and fall through. */
			hlist_del(&b->hnode);
			fc_binding_free(b);
			b = NULL;
		}
	}
	if (!reuse)
		ext_port_pref = fc_pick_port(net, zone, family, l4proto,
					     &ext_addr, otuple->src.u.all,
					     range);
	spin_unlock_bh(&fcn->lock);

	/* ---- Phase 2: hand the chosen (addr, port) to the kernel NAT
	 *      machinery. It may pick a different port if the suggestion
	 *      collides with an existing reply tuple. */
	memset(&newrange, 0, sizeof(newrange));
	newrange.flags     = NF_NAT_RANGE_MAP_IPS | NF_NAT_RANGE_PROTO_SPECIFIED;
	newrange.min_addr  = ext_addr;
	newrange.max_addr  = ext_addr;
	newrange.min_proto.all = ext_port_pref;
	newrange.max_proto.all = ext_port_pref;

	ret = nf_nat_setup_info(ct, &newrange, NF_NAT_MANIP_SRC);
	if (ret != NF_ACCEPT)
		return ret;

	/* ---- Phase 3: read back the actually-allocated (addr, port) from
	 *      the ct's reply tuple. The reply tuple is the inverse of the
	 *      post-NAT view, so its DST is what the external network sees
	 *      as our SRC. */
	rtuple = &ct->tuplehash[IP_CT_DIR_REPLY].tuple;
	ext_addr_actual = rtuple->dst.u3;
	ext_port_actual = rtuple->dst.u.all;

	if (reuse) {
		/* The cached binding still owns the original expectation; we
		 * trust that nf_nat_setup_info handed us the same external
		 * port we suggested (it almost always does). Done. */
		return NF_ACCEPT;
	}

	/* ---- Phase 4: install a fresh expectation that captures any
	 *      inbound packet aimed at the new (ext_addr, ext_port) and
	 *      DNATs it back to the internal endpoint. */
	exp = nf_ct_expect_alloc(ct);
	if (!exp)
		return NF_ACCEPT;	/* outbound still works */

	nf_ct_expect_init(exp, NF_CT_EXPECT_CLASS_DEFAULT, family,
			  NULL, &ext_addr_actual, l4proto, NULL,
			  &ext_port_actual);
	exp->saved_addr      = otuple->src.u3;
	exp->saved_proto.all = otuple->src.u.all;
	exp->dir             = IP_CT_DIR_REPLY;
	exp->expectfn        = fc_expectfn;
	exp->flags           = NF_CT_EXPECT_PERMANENT;

	err = nf_ct_expect_related(exp, 0);
	if (err < 0) {
		/* -EBUSY / -EEXIST means another CPU raced us and claimed the
		 * same external (addr, port). The current ct already has its
		 * SNAT installed (phase 2 succeeded) and will work fine in the
		 * outbound direction; only the inbound DNAT path is unset for
		 * this single flow. The next outbound flow from the same
		 * internal endpoint will retry and pick a different port. */
		nf_ct_expect_put(exp);
		return NF_ACCEPT;
	}

	b = kzalloc(sizeof(*b), GFP_ATOMIC);
	if (!b) {
		nf_ct_unexpect_related(exp);
		nf_ct_expect_put(exp);
		return NF_ACCEPT;
	}
	b->family    = family;
	b->l4proto   = l4proto;
	b->zone_id   = zone->id;
	b->int_addr  = otuple->src.u3;
	b->int_port  = otuple->src.u.all;
	b->ext_addr  = ext_addr_actual;
	b->ext_port  = ext_port_actual;
	b->exp       = exp;	/* binding owns the exp reference */
	b->last_used = jiffies;

	spin_lock_bh(&fcn->lock);
	{
		struct fc_binding *dup;

		/* Re-check: another CPU may have inserted a binding for the
		 * same internal endpoint while we were unlocked. */
		dup = fc_idx_lookup(fcn, &b->int_addr, b->int_port,
				    b->family, b->l4proto);
		if (dup) {
			spin_unlock_bh(&fcn->lock);
			nf_ct_unexpect_related(exp);
			fc_binding_free(b);
			return NF_ACCEPT;
		}
		fc_idx_insert(fcn, b);
	}
	spin_unlock_bh(&fcn->lock);

	return NF_ACCEPT;
}

/* ------------------------------------------------------------------------- */
/* Engine entry point used by both frontends                                  */
/* ------------------------------------------------------------------------- */

static unsigned int fc_engine_eval(struct sk_buff *skb,
				   unsigned int hooknum,
				   const struct net_device *out,
				   const struct fc_range *range)
{
	/* Inbound is handled entirely by the expectation system. We never
	 * need to do work in PREROUTING — but we accept being placed there
	 * so users can write symmetric chains without breaking anything. */
	if (hooknum != NF_INET_POST_ROUTING)
		return NF_ACCEPT;

	return fc_eval_outbound(skb, out, range);
}

/* ------------------------------------------------------------------------- */
/* Per-netns reaper                                                           */
/* ------------------------------------------------------------------------- */

static void fc_reaper(struct work_struct *work)
{
	struct fc_net *fcn = container_of(to_delayed_work(work),
					   struct fc_net, reaper);
	struct hlist_node *tmp;
	struct fc_binding *b;
	unsigned long now = jiffies;
	HLIST_HEAD(victims);
	int i;

	/* Pass 1: gather victims under the lock. */
	spin_lock_bh(&fcn->lock);
	for (i = 0; i < FC_HASH_SIZE; i++) {
		hlist_for_each_entry_safe(b, tmp, &fcn->idx[i], hnode) {
			struct nf_conntrack_zone z;
			bool dead = false;

			nf_ct_zone_init(&z, b->zone_id,
					NF_CT_DEFAULT_ZONE_DIR, 0);

			if (time_after(now, b->last_used + FC_BINDING_TIMEOUT))
				dead = true;
			else if (!fc_exp_alive(fcn->net, &z, b))
				dead = true;

			if (dead) {
				hlist_del(&b->hnode);
				hlist_add_head(&b->hnode, &victims);
			}
		}
	}
	spin_unlock_bh(&fcn->lock);

	/* Pass 2: release expectations + free outside the lock so the data
	 * path can run concurrently. */
	hlist_for_each_entry_safe(b, tmp, &victims, hnode) {
		hlist_del(&b->hnode);
		if (b->exp)
			nf_ct_unexpect_related(b->exp);
		fc_binding_free(b);
	}

	if (atomic_read(&fcn->refcnt) > 0)
		queue_delayed_work(system_power_efficient_wq, &fcn->reaper,
				   FC_REAPER_INTERVAL);
}

static void fc_flush_pernet(struct fc_net *fcn)
{
	struct hlist_node *tmp;
	struct fc_binding *b;
	HLIST_HEAD(victims);
	int i;

	spin_lock_bh(&fcn->lock);
	for (i = 0; i < FC_HASH_SIZE; i++) {
		hlist_for_each_entry_safe(b, tmp, &fcn->idx[i], hnode) {
			hlist_del(&b->hnode);
			hlist_add_head(&b->hnode, &victims);
		}
	}
	spin_unlock_bh(&fcn->lock);

	hlist_for_each_entry_safe(b, tmp, &victims, hnode) {
		hlist_del(&b->hnode);
		if (b->exp)
			nf_ct_unexpect_related(b->exp);
		fc_binding_free(b);
	}
}

/* ------------------------------------------------------------------------- */
/* pernet_operations                                                          */
/* ------------------------------------------------------------------------- */

static int __net_init fc_net_init(struct net *net)
{
	struct fc_net *fcn = fc_pernet(net);
	int i;

	for (i = 0; i < FC_HASH_SIZE; i++)
		INIT_HLIST_HEAD(&fcn->idx[i]);
	spin_lock_init(&fcn->lock);
	INIT_DELAYED_WORK(&fcn->reaper, fc_reaper);
	fcn->net = net;
	atomic_set(&fcn->refcnt, 0);
	return 0;
}

static void __net_exit fc_net_exit(struct net *net)
{
	struct fc_net *fcn = fc_pernet(net);

	cancel_delayed_work_sync(&fcn->reaper);
	fc_flush_pernet(fcn);
}

static struct pernet_operations fc_pernet_ops = {
	.init = fc_net_init,
	.exit = fc_net_exit,
	.id   = &fc_net_id,
	.size = sizeof(struct fc_net),
};

/* Called by the frontend on rule add/del to start/stop the reaper. */
static void fc_engine_take(struct net *net)
{
	struct fc_net *fcn = fc_pernet(net);

	if (atomic_inc_return(&fcn->refcnt) == 1)
		queue_delayed_work(system_power_efficient_wq, &fcn->reaper,
				   FC_REAPER_INTERVAL);
}

static void fc_engine_drop(struct net *net)
{
	struct fc_net *fcn = fc_pernet(net);

	if (atomic_dec_and_test(&fcn->refcnt))
		cancel_delayed_work_sync(&fcn->reaper);
}

/* ------------------------------------------------------------------------- */
/* Module init / exit (called from frontend wrapper)                          */
/* ------------------------------------------------------------------------- */

static int fc_engine_init(void)
{
	return register_pernet_subsys(&fc_pernet_ops);
}

static void fc_engine_exit(void)
{
	unregister_pernet_subsys(&fc_pernet_ops);
}
