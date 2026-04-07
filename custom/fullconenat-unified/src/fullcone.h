/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Unified Full Cone NAT kernel module
 *
 * Uses conntrack expectations for port mapping storage.
 * Supports IPv4/IPv6, UDP/TCP, iptables/nftables.
 */
#ifndef _FULLCONE_H
#define _FULLCONE_H

#include <linux/module.h>
#include <linux/version.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>
#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_expect.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/netfilter/nf_conntrack_core.h>

/* Expect policy limits */
#define FULLCONE_MAX_EXPECTED   4096
#define FULLCONE_EXPECT_TIMEOUT 300

/* Port allocation range */
#define FULLCONE_PORT_MIN       1024
#define FULLCONE_PORT_MAX       65535

/* Helper index enum */
enum fullcone_helper_id {
	FULLCONE_HELPER_UDP4 = 0,
	FULLCONE_HELPER_UDP6,
	FULLCONE_HELPER_TCP4,
	FULLCONE_HELPER_TCP6,
	FULLCONE_HELPER_MAX,
};

/* Helper array accessible from xt/nft frontends */
extern struct nf_conntrack_helper fullcone_helpers[FULLCONE_HELPER_MAX];

/* Core API called by xt and nft frontends */
unsigned int fullcone_do_postrouting(struct sk_buff *skb,
				     const struct net_device *out,
				     sa_family_t family);

unsigned int fullcone_do_prerouting(struct sk_buff *skb,
				    sa_family_t family);

/* Module core init/exit (registers helpers) */
int fullcone_core_init(void);
void fullcone_core_exit(void);

/* NFT expression registration (called from module init) */
int fullcone_nft_init(void);
void fullcone_nft_exit(void);

#endif /* _FULLCONE_H */
