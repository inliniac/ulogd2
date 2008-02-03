/* ulogd_filter_IP2BIN.c, Version $Revision: 1500 $
 *
 * ulogd interpreter plugin for internal IP storage format to binary conversion
 *
 * (C) 2008 by Eric Leblond <eric@inl.fr>
 *
 * Based on ulogd_filter_IFINDEX.c Harald Welte <laforge@gnumonks.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * $Id: ulogd_filter_IFINDEX.c 1500 2005-10-03 16:54:02Z laforge $
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <ulogd/ulogd.h>

#define IPADDR_LENGTH 128

enum input_keys {
	KEY_OOB_FAMILY,
	KEY_IP_SADDR,
	START_KEY = KEY_IP_SADDR,
	KEY_IP_DADDR,
	KEY_ORIG_IP_SADDR,
	KEY_ORIG_IP_DADDR,
	KEY_REPLY_IP_SADDR,
	KEY_REPLY_IP_DADDR,
	MAX_KEY = KEY_REPLY_IP_DADDR,
};

static struct ulogd_key ip2bin_inp[] = {
	[KEY_OOB_FAMILY] = {
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.family",
	},
	[KEY_IP_SADDR] = {
		.type = ULOGD_RET_IPADDR,
		.flags = ULOGD_RETF_NONE|ULOGD_KEYF_OPTIONAL,
		.name = "ip.saddr",
	},
	[KEY_IP_DADDR] = {
		.type = ULOGD_RET_IPADDR,
		.flags = ULOGD_RETF_NONE|ULOGD_KEYF_OPTIONAL,
		.name = "ip.daddr",
	},
	[KEY_ORIG_IP_SADDR] = {
		.type 	= ULOGD_RET_IPADDR,
		.flags 	= ULOGD_RETF_NONE|ULOGD_KEYF_OPTIONAL,
		.name	= "orig.ip.saddr",
	},
	[KEY_ORIG_IP_DADDR] = {
		.type	= ULOGD_RET_IPADDR,
		.flags	= ULOGD_RETF_NONE|ULOGD_KEYF_OPTIONAL,
		.name	= "orig.ip.daddr",
	},
	[KEY_REPLY_IP_SADDR] = {
		.type 	= ULOGD_RET_IPADDR,
		.flags 	= ULOGD_RETF_NONE|ULOGD_KEYF_OPTIONAL,
		.name	= "reply.ip.saddr",
	},
	[KEY_REPLY_IP_DADDR] = {
		.type	= ULOGD_RET_IPADDR,
		.flags	= ULOGD_RETF_NONE|ULOGD_KEYF_OPTIONAL,
		.name	= "reply.ip.daddr",
	},
};

static struct ulogd_key ip2bin_keys[] = {
	{
		.type = ULOGD_RET_RAW,
		.flags = ULOGD_RETF_FREE,
		.name = "ip.saddr.bin",
	},
	{
		.type = ULOGD_RET_RAW,
		.flags = ULOGD_RETF_FREE,
		.name = "ip.daddr.bin",
	},
	{
		.type = ULOGD_RET_RAW,
		.flags = ULOGD_RETF_FREE,
		.name = "orig.ip.saddr.bin",
	},
	{
		.type = ULOGD_RET_RAW,
		.flags = ULOGD_RETF_FREE,
		.name = "orig.ip.daddr.bin",
	},
	{
		.type = ULOGD_RET_RAW,
		.flags = ULOGD_RETF_FREE,
		.name = "reply.ip.saddr.bin",
	},
	{
		.type = ULOGD_RET_RAW,
		.flags = ULOGD_RETF_FREE,
		.name = "reply.ip.daddr.bin",
	},

};

#define GET_VALUE(res, x)	(res[x].u.source->u.value)
#define GET_FLAGS(res, x)	(res[x].u.source->flags)
#define pp_is_valid(res, x)	\
	(res[x].u.source && (GET_FLAGS(res, x) & ULOGD_RETF_VALID))

/**
 * Convert IPv4 address (as 32-bit unsigned integer) to IPv6 address:
 * add 96 bits prefix "::ffff:" to get IPv6 address "::ffff:a.b.c.d".
 */
inline void uint32_to_ipv6(const uint32_t ipv4, struct in6_addr *ipv6)
{
	ipv6->s6_addr32[0] = 0x00000000;
	ipv6->s6_addr32[1] = 0x00000000;
	ipv6->s6_addr32[2] = htonl(0xffff);
	ipv6->s6_addr32[3] = ipv4;
}

static char *ip2bin(struct ulogd_key* inp, int index, char family)
{
	char tmp[IPADDR_LENGTH];
	unsigned char *addr8;
	struct in6_addr *addr;
	struct in6_addr ip4_addr;
	char *buffer;
	int i, written;

	switch (family) {
		case AF_INET6:
			addr = GET_VALUE(inp, index).ptr;
			break;
		case AF_INET:
			/* Convert IPv4 to IPv4 in IPv6 */
			addr = &ip4_addr;
			uint32_to_ipv6(GET_VALUE(inp, index).ui32, addr);
			break;
		default:
			/* TODO handle error */
			ulogd_log(ULOGD_NOTICE, "Unknown protocol family\n");
			return;
	}

	buffer = tmp;
	/* format IPv6 to BINARY(16) as "0x..." */
	buffer[0] = '0';
	buffer[1] = 'x';
	buffer += 2;
	addr8 = &addr->s6_addr[0];
	for (i = 0; i < 4; i++) {
		written = sprintf(buffer, "%02x%02x%02x%02x",
				addr8[0], addr8[1], addr8[2], addr8[3]);
		if (written != 2 * 4) {
			buffer[0] = 0;
			return;
		}
		buffer += written;
		addr8 += 4;
	}
	buffer[0] = 0;

	return strdup(tmp);
}

static int interp_ip2bin(struct ulogd_pluginstance *pi)
{
	struct ulogd_key *ret = pi->output.keys;
	struct ulogd_key *inp = pi->input.keys;
	int i;
	int oob_family = GET_VALUE(inp, KEY_OOB_FAMILY).ui8;

	/* Iter on all addr fields */
	for(i = START_KEY; i < MAX_KEY; i++) {
		if (pp_is_valid(inp, i)) {
			ret[i-1].u.value.ptr = ip2bin(inp, i, oob_family);
			ret[i-1].flags |= ULOGD_RETF_VALID;
		}
	}

	return 0;
}

static struct ulogd_plugin ip2bin_pluging = {
	.name = "IP2BIN",
	.input = {
		.keys = ip2bin_inp,
		.num_keys = ARRAY_SIZE(ip2bin_inp),
		.type = ULOGD_DTYPE_PACKET | ULOGD_DTYPE_FLOW,
		},
	.output = {
		.keys = ip2bin_keys,
		.num_keys = ARRAY_SIZE(ip2bin_keys),
		.type = ULOGD_DTYPE_PACKET | ULOGD_DTYPE_FLOW,
		},
	.interp = &interp_ip2bin,
	.version = ULOGD_VERSION,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	ulogd_register_plugin(&ip2bin_pluging);
}
