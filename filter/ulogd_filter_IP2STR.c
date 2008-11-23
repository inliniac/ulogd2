/* ulogd_filter_IP2STR.c, Version $Revision: 1500 $
 *
 * ulogd interpreter plugin for internal IP storage format to string conversion
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
#include <netinet/if_ether.h>

#define IPADDR_LENGTH 128

enum input_keys {
	KEY_OOB_FAMILY,
	KEY_OOB_PROTOCOL,
	KEY_IP_SADDR,
	START_KEY = KEY_IP_SADDR,
	KEY_IP_DADDR,
	KEY_ORIG_IP_SADDR,
	KEY_ORIG_IP_DADDR,
	KEY_REPLY_IP_SADDR,
	KEY_REPLY_IP_DADDR,
	KEY_ARP_SPA,
	KEY_ARP_TPA,
	MAX_KEY = KEY_ARP_TPA,
};

static struct ulogd_key ip2str_inp[] = {
	[KEY_OOB_FAMILY] = {
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.family",
	},
	[KEY_OOB_PROTOCOL] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.protocol",
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
	[KEY_ARP_SPA] = {
		.type = ULOGD_RET_IPADDR,
		.flags = ULOGD_RETF_NONE|ULOGD_KEYF_OPTIONAL,
		.name = "arp.saddr",
	},
	[KEY_ARP_TPA] = {
		.type = ULOGD_RET_IPADDR,
		.flags = ULOGD_RETF_NONE|ULOGD_KEYF_OPTIONAL,
		.name = "arp.daddr",
	},
};

static struct ulogd_key ip2str_keys[] = {
	{
		.type = ULOGD_RET_STRING,
		.flags = ULOGD_RETF_FREE,
		.name = "ip.saddr.str",
	},
	{
		.type = ULOGD_RET_STRING,
		.flags = ULOGD_RETF_FREE,
		.name = "ip.daddr.str",
	},
	{
		.type = ULOGD_RET_STRING,
		.flags = ULOGD_RETF_FREE,
		.name = "orig.ip.saddr.str",
	},
	{
		.type = ULOGD_RET_STRING,
		.flags = ULOGD_RETF_FREE,
		.name = "orig.ip.daddr.str",
	},
	{
		.type = ULOGD_RET_STRING,
		.flags = ULOGD_RETF_FREE,
		.name = "reply.ip.saddr.str",
	},
	{
		.type = ULOGD_RET_STRING,
		.flags = ULOGD_RETF_FREE,
		.name = "reply.ip.daddr.str",
	},
	{
		.type = ULOGD_RET_STRING,
		.flags = ULOGD_RETF_FREE,
		.name = "arp.saddr.str",
	},
	{
		.type = ULOGD_RET_STRING,
		.flags = ULOGD_RETF_FREE,
		.name = "arp.daddr.str",
	},
};

static char *ip2str(struct ulogd_key *inp, int index)
{
	char tmp[IPADDR_LENGTH];
	char family = ikey_get_u8(&inp[KEY_OOB_FAMILY]);
	char convfamily = family;

	if (family == AF_BRIDGE) {
		if (!pp_is_valid(inp, KEY_OOB_PROTOCOL)) {
			ulogd_log(ULOGD_NOTICE,
				  "No protocol inside AF_BRIDGE packet\n");
			return NULL;
		}
		switch (ikey_get_u16(&inp[KEY_OOB_PROTOCOL])) {
		case ETH_P_IPV6:
			convfamily = AF_INET6;
			break;
		case ETH_P_IP:
			convfamily = AF_INET;
			break;
		case ETH_P_ARP:
			convfamily = AF_INET;
			break;
		default:
			ulogd_log(ULOGD_NOTICE,
				  "Unknown protocol inside AF_BRIDGE packet\n");
			return NULL;
		}
	}

	switch (convfamily) {
		u_int32_t ip;
	case AF_INET6:
		inet_ntop(AF_INET6,
			  ikey_get_u128(&inp[index]),
			  tmp, sizeof(tmp));
		break;
	case AF_INET:
		ip = ikey_get_u32(&inp[index]);
		inet_ntop(AF_INET, &ip, tmp, sizeof(tmp));
		break;
	default:
		/* TODO error handling */
		ulogd_log(ULOGD_NOTICE, "Unknown protocol family\n");
		return NULL;
	}
	return strdup(tmp);
}

static int interp_ip2str(struct ulogd_pluginstance *pi)
{
	struct ulogd_key *ret = pi->output.keys;
	struct ulogd_key *inp = pi->input.keys;
	int i;

	/* Iter on all addr fields */
	for (i = START_KEY; i <= MAX_KEY; i++) {
		if (pp_is_valid(inp, i)) {
			okey_set_ptr(&ret[i-START_KEY], ip2str(inp, i));
		}
	}

	return ULOGD_IRET_OK;
}

static struct ulogd_plugin ip2str_pluging = {
	.name = "IP2STR",
	.input = {
		.keys = ip2str_inp,
		.num_keys = ARRAY_SIZE(ip2str_inp),
		.type = ULOGD_DTYPE_PACKET | ULOGD_DTYPE_FLOW,
		},
	.output = {
		.keys = ip2str_keys,
		.num_keys = ARRAY_SIZE(ip2str_keys),
		.type = ULOGD_DTYPE_PACKET | ULOGD_DTYPE_FLOW,
		},
	.interp = &interp_ip2str,
	.version = ULOGD_VERSION,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	ulogd_register_plugin(&ip2str_pluging);
}
