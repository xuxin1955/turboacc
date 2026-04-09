/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * libxt_FULLCONE.c - userspace iptables/ip6tables extension for FULLCONE.
 *
 * Builds as libxt_FULLCONE.so and is loaded by iptables/ip6tables when the
 * user writes "-j FULLCONE". Recognizes the same option set as MASQUERADE
 * plus an explicit "--to-source" / "--to-ports" pair.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <limits.h>

#include <xtables.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_nat.h>

#include "xt_FULLCONE.h"

enum {
	O_TO_PORTS = 0,
	O_TO_SOURCE,
	O_RANDOM,
	O_RANDOM_FULLY,
	O_PERSISTENT,
};

static const struct xt_option_entry FULLCONE_opts[] = {
	{ .name = "to-ports",     .id = O_TO_PORTS,     .type = XTTYPE_STRING },
	{ .name = "to-source",    .id = O_TO_SOURCE,    .type = XTTYPE_STRING },
	{ .name = "random",       .id = O_RANDOM,       .type = XTTYPE_NONE   },
	{ .name = "random-fully", .id = O_RANDOM_FULLY, .type = XTTYPE_NONE   },
	{ .name = "persistent",   .id = O_PERSISTENT,   .type = XTTYPE_NONE   },
	XTOPT_TABLEEND,
};

static void FULLCONE_help(void)
{
	printf(
"FULLCONE target options:\n"
" --to-source <ipaddr>[-<ipaddr>]   External source address (range)\n"
" --to-ports  <port>[-<port>]       External port range\n"
" --random                          Randomize source port (legacy)\n"
" --random-fully                    Fully randomize source port\n"
" --persistent                      Enable for TCP too (default UDP only)\n");
}

static void FULLCONE_init(struct xt_entry_target *t)
{
	struct xt_fullcone_tginfo *info = (void *)t->data;
	memset(info, 0, sizeof(*info));
}

static void parse_to_source4(const char *arg, struct xt_fullcone_tginfo *info)
{
	char buf[64], *dash;
	const struct in_addr *ip;

	if (strlen(arg) >= sizeof(buf))
		xtables_error(PARAMETER_PROBLEM, "address too long");
	strncpy(buf, arg, sizeof(buf) - 1);
	buf[sizeof(buf) - 1] = '\0';

	dash = strchr(buf, '-');
	if (dash)
		*dash = '\0';

	ip = xtables_numeric_to_ipaddr(buf);
	if (!ip)
		xtables_error(PARAMETER_PROBLEM, "bad IPv4 address \"%s\"", buf);
	info->min_addr.ip = ip->s_addr;

	if (dash) {
		ip = xtables_numeric_to_ipaddr(dash + 1);
		if (!ip)
			xtables_error(PARAMETER_PROBLEM,
				      "bad IPv4 address \"%s\"", dash + 1);
		info->max_addr.ip = ip->s_addr;
	} else {
		info->max_addr.ip = info->min_addr.ip;
	}
	info->flags |= NF_NAT_RANGE_MAP_IPS;
}

static void parse_to_source6(const char *arg, struct xt_fullcone_tginfo *info)
{
	char buf[INET6_ADDRSTRLEN + 1], *dash;
	const struct in6_addr *ip;

	if (strlen(arg) >= sizeof(buf))
		xtables_error(PARAMETER_PROBLEM, "address too long");
	strncpy(buf, arg, sizeof(buf) - 1);
	buf[sizeof(buf) - 1] = '\0';

	dash = strchr(buf, '-');
	if (dash)
		*dash = '\0';

	ip = xtables_numeric_to_ip6addr(buf);
	if (!ip)
		xtables_error(PARAMETER_PROBLEM, "bad IPv6 address \"%s\"", buf);
	info->min_addr.in6 = *ip;

	if (dash) {
		ip = xtables_numeric_to_ip6addr(dash + 1);
		if (!ip)
			xtables_error(PARAMETER_PROBLEM,
				      "bad IPv6 address \"%s\"", dash + 1);
		info->max_addr.in6 = *ip;
	} else {
		info->max_addr.in6 = info->min_addr.in6;
	}
	info->flags |= NF_NAT_RANGE_MAP_IPS;
}

static void parse_ports(const char *arg, struct xt_fullcone_tginfo *info)
{
	unsigned int p, q;
	char *end;

	if (!xtables_strtoui(arg, &end, &p, 0, UINT16_MAX))
		xtables_error(PARAMETER_PROBLEM, "bad port \"%s\"", arg);

	switch (*end) {
	case '\0':
		info->min_port = info->max_port = htons(p);
		break;
	case '-':
		if (!xtables_strtoui(end + 1, NULL, &q, 0, UINT16_MAX) || q < p)
			xtables_error(PARAMETER_PROBLEM, "bad port range \"%s\"", arg);
		info->min_port = htons(p);
		info->max_port = htons(q);
		break;
	default:
		xtables_error(PARAMETER_PROBLEM, "bad port \"%s\"", arg);
	}
	info->flags |= NF_NAT_RANGE_PROTO_SPECIFIED;
}

static void FULLCONE4_parse(struct xt_option_call *cb)
{
	struct xt_fullcone_tginfo *info = cb->data;

	xtables_option_parse(cb);
	switch (cb->entry->id) {
	case O_TO_SOURCE:
		parse_to_source4(cb->arg, info);
		break;
	case O_TO_PORTS:
		parse_ports(cb->arg, info);
		break;
	case O_RANDOM:
		info->flags |= NF_NAT_RANGE_PROTO_RANDOM;
		break;
	case O_RANDOM_FULLY:
		info->flags |= NF_NAT_RANGE_PROTO_RANDOM_FULLY;
		break;
	case O_PERSISTENT:
		info->flags |= NF_NAT_RANGE_PERSISTENT;
		break;
	}
}

static void FULLCONE6_parse(struct xt_option_call *cb)
{
	struct xt_fullcone_tginfo *info = cb->data;

	xtables_option_parse(cb);
	switch (cb->entry->id) {
	case O_TO_SOURCE:
		parse_to_source6(cb->arg, info);
		break;
	case O_TO_PORTS:
		parse_ports(cb->arg, info);
		break;
	case O_RANDOM:
		info->flags |= NF_NAT_RANGE_PROTO_RANDOM;
		break;
	case O_RANDOM_FULLY:
		info->flags |= NF_NAT_RANGE_PROTO_RANDOM_FULLY;
		break;
	case O_PERSISTENT:
		info->flags |= NF_NAT_RANGE_PERSISTENT;
		break;
	}
}

static void print_common(const struct xt_fullcone_tginfo *info, int af,
			 const char *prefix)
{
	if (info->flags & NF_NAT_RANGE_MAP_IPS) {
		if (af == NFPROTO_IPV4) {
			struct in_addr a;
			a.s_addr = info->min_addr.ip;
			printf(" %sto-source %s", prefix, inet_ntoa(a));
			if (info->max_addr.ip != info->min_addr.ip) {
				a.s_addr = info->max_addr.ip;
				printf("-%s", inet_ntoa(a));
			}
		} else {
			char buf[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, &info->min_addr.in6, buf, sizeof(buf));
			printf(" %sto-source %s", prefix, buf);
			if (memcmp(&info->min_addr.in6, &info->max_addr.in6,
				   sizeof(struct in6_addr)) != 0) {
				inet_ntop(AF_INET6, &info->max_addr.in6, buf, sizeof(buf));
				printf("-%s", buf);
			}
		}
	}
	if (info->flags & NF_NAT_RANGE_PROTO_SPECIFIED) {
		printf(" %sto-ports %u", prefix, ntohs(info->min_port));
		if (info->max_port != info->min_port)
			printf("-%u", ntohs(info->max_port));
	}
	if (info->flags & NF_NAT_RANGE_PROTO_RANDOM)
		printf(" %srandom", prefix);
	if (info->flags & NF_NAT_RANGE_PROTO_RANDOM_FULLY)
		printf(" %srandom-fully", prefix);
	if (info->flags & NF_NAT_RANGE_PERSISTENT)
		printf(" %spersistent", prefix);
}

static void FULLCONE4_print(const void *ip, const struct xt_entry_target *t, int n)
{
	print_common((const void *)t->data, NFPROTO_IPV4, "");
}

static void FULLCONE4_save(const void *ip, const struct xt_entry_target *t)
{
	print_common((const void *)t->data, NFPROTO_IPV4, "--");
}

static void FULLCONE6_print(const void *ip, const struct xt_entry_target *t, int n)
{
	print_common((const void *)t->data, NFPROTO_IPV6, "");
}

static void FULLCONE6_save(const void *ip, const struct xt_entry_target *t)
{
	print_common((const void *)t->data, NFPROTO_IPV6, "--");
}

static struct xtables_target fullcone_tg_reg[] = {
	{
		.name          = "FULLCONE",
		.version       = XTABLES_VERSION,
		.family        = NFPROTO_IPV4,
		.size          = XT_ALIGN(sizeof(struct xt_fullcone_tginfo)),
		.userspacesize = XT_ALIGN(sizeof(struct xt_fullcone_tginfo)),
		.help          = FULLCONE_help,
		.init          = FULLCONE_init,
		.x6_parse      = FULLCONE4_parse,
		.print         = FULLCONE4_print,
		.save          = FULLCONE4_save,
		.x6_options    = FULLCONE_opts,
	},
	{
		.name          = "FULLCONE",
		.version       = XTABLES_VERSION,
		.family        = NFPROTO_IPV6,
		.size          = XT_ALIGN(sizeof(struct xt_fullcone_tginfo)),
		.userspacesize = XT_ALIGN(sizeof(struct xt_fullcone_tginfo)),
		.help          = FULLCONE_help,
		.init          = FULLCONE_init,
		.x6_parse      = FULLCONE6_parse,
		.print         = FULLCONE6_print,
		.save          = FULLCONE6_save,
		.x6_options    = FULLCONE_opts,
	},
};

static void __attribute__((constructor)) libxt_FULLCONE_init(void)
{
	xtables_register_targets(fullcone_tg_reg,
				 sizeof(fullcone_tg_reg) / sizeof(fullcone_tg_reg[0]));
}
