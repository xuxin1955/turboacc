/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * xt_FULLCONE.h - shared user/kernel ABI for the iptables FULLCONE target.
 *
 * Kept deliberately small and version-stable: the layout below is what the
 * userspace libxt_FULLCONE.so writes into the rule blob, and what the kernel
 * xt_FULLCONE.ko reads.  Adding fields requires bumping the target revision.
 */
#ifndef _XT_FULLCONE_H_
#define _XT_FULLCONE_H_

#include <linux/types.h>
#include <linux/netfilter.h>

struct xt_fullcone_tginfo {
	__u32			flags;		/* NF_NAT_RANGE_* */
	union nf_inet_addr	min_addr;
	union nf_inet_addr	max_addr;
	__be16			min_port;
	__be16			max_port;
	__u8			pad[4];
};

#endif /* _XT_FULLCONE_H_ */
