/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * fc_engine.h - public types for the unified fullcone NAT engine.
 *
 * The engine .c file is intentionally `#include`-d directly into each
 * frontend translation unit so that ALL its symbols are file-static and
 * never escape the resulting .ko. This is what lets us ship two completely
 * independent kernel modules (xt_FULLCONE.ko / nft_FULLCONE.ko) from a
 * single source file without any inter-module symbol coupling. As a result
 * this header contains only types — never function declarations.
 */
#ifndef _FC_ENGINE_H_
#define _FC_ENGINE_H_

#include <linux/types.h>
#include <net/netfilter/nf_nat.h>

/* User-supplied NAT range, abstracted away from any iptables/nftables type
 * so that neither frontend pulls in the other's headers. Both frontends fill
 * this in from their own user-facing config struct and pass it to the
 * engine. */
struct fc_range {
	__u32			flags;		/* NF_NAT_RANGE_* */
	__u8			family;		/* NFPROTO_IPV4 / NFPROTO_IPV6 */
	union nf_inet_addr	min_addr;
	union nf_inet_addr	max_addr;
	__be16			min_port;	/* network order; 0 = any */
	__be16			max_port;
};

#endif /* _FC_ENGINE_H_ */
