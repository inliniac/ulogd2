/* ulogd_filter_HWHDR.c
 *
 * ulogd interpreter plugin for HWMAC
 *
 * (C) 2008 by Eric Leblond <eric@inl.fr>
 * (C) 2008 by Pablo Neira Ayuso <pablo@netfilter.org>
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
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <ulogd/ulogd.h>

#define HWADDR_LENGTH 128

enum input_keys {
	KEY_RAW_TYPE,
	KEY_OOB_PROTOCOL,
	KEY_RAW_MAC,
	KEY_RAW_MACLEN,
	KEY_RAW_MAC_SADDR,
	KEY_RAW_MAC_ADDRLEN,
};

enum output_keys {
	KEY_MAC_TYPE,
	KEY_MAC_PROTOCOL,
	KEY_MAC_SADDR,
	START_KEY = KEY_MAC_SADDR,
	KEY_MAC_DADDR,
	KEY_MAC_ADDR,
	MAX_KEY = KEY_MAC_ADDR,
};

static struct ulogd_key mac2str_inp[] = {
	[KEY_RAW_TYPE] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE|ULOGD_KEYF_OPTIONAL,
		.name = "raw.type",
	},
	[KEY_OOB_PROTOCOL] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.protocol",
	},
	[KEY_RAW_MAC] = {
		.type = ULOGD_RET_RAW,
		.flags = ULOGD_RETF_NONE|ULOGD_KEYF_OPTIONAL,
		.name = "raw.mac",
	},
	[KEY_RAW_MACLEN] = { 
		.type = ULOGD_RET_UINT16, 
		.flags = ULOGD_RETF_NONE|ULOGD_KEYF_OPTIONAL,
		.name = "raw.mac_len", 
	},
	[KEY_RAW_MAC_SADDR] = {
		.type = ULOGD_RET_RAW,
		.flags = ULOGD_RETF_NONE|ULOGD_KEYF_OPTIONAL,
		.name = "raw.mac.saddr",
	},
	[KEY_RAW_MAC_ADDRLEN] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE|ULOGD_KEYF_OPTIONAL,
		.name = "raw.mac.addrlen",
	},
};

static struct ulogd_key mac2str_keys[] = {
	[KEY_MAC_TYPE] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "raw.type",
	},
	[KEY_MAC_PROTOCOL] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.protocol",
	},
	[KEY_MAC_SADDR] = {
		.type = ULOGD_RET_STRING,
		.name = "mac.saddr.str",
	},
	[KEY_MAC_DADDR] = {
		.type = ULOGD_RET_STRING,
		.name = "mac.daddr.str",
	},
	[KEY_MAC_ADDR] = {
		.type = ULOGD_RET_STRING,
		.name = "mac.str",
	},
};

static char hwmac_str[MAX_KEY - START_KEY][HWADDR_LENGTH];

static int parse_mac2str(struct ulogd_key *ret, unsigned char *mac,
			 int okey, int len)
{
	char *buf_cur;
	int i;

	if (len * 3 + 1 > HWADDR_LENGTH)
		return ULOGD_IRET_ERR;

	if (len == 0)
		hwmac_str[okey - START_KEY][0] = 0;

	buf_cur = hwmac_str[okey - START_KEY];
	for (i = 0; i < len; i++)
		buf_cur += sprintf(buf_cur, "%02x%c", mac[i],
				i == len - 1 ? 0 : ':');

	okey_set_ptr(&ret[okey], hwmac_str[okey - START_KEY]);

	return ULOGD_IRET_OK;
}

static void *hwhdr_get_saddr(struct ulogd_key *inp)
{
	return ikey_get_ptr(&inp[KEY_RAW_MAC]) + ETH_ALEN;
}

static void *hwhdr_get_daddr(struct ulogd_key *inp)
{
	return ikey_get_ptr(&inp[KEY_RAW_MAC]);
}

static u_int16_t hwhdr_get_len(struct ulogd_key *inp)
{
	void *len = ikey_get_ptr(&inp[KEY_RAW_MAC]) + 2 * ETH_ALEN;
	return ntohs(*(u_int16_t *) len);
}
static int parse_ethernet(struct ulogd_key *ret, struct ulogd_key *inp)
{
	int fret;
	if (!pp_is_valid(inp, KEY_RAW_MAC_SADDR)) {
		fret = parse_mac2str(ret, hwhdr_get_saddr(inp),
				     KEY_MAC_SADDR, ETH_ALEN);
		if (fret != ULOGD_IRET_OK)
			return fret;
	}
	fret = parse_mac2str(ret, hwhdr_get_daddr(inp),
			     KEY_MAC_DADDR, ETH_ALEN);
	if (fret != ULOGD_IRET_OK)
		return fret;

	okey_set_u16(&ret[KEY_MAC_PROTOCOL], hwhdr_get_len(inp));

	return ULOGD_IRET_OK;
}

static int interp_mac2str(struct ulogd_pluginstance *pi)
{
	struct ulogd_key *ret = pi->output.keys;
	struct ulogd_key *inp = pi->input.keys;
	u_int16_t type = 0;

	if (pp_is_valid(inp, KEY_OOB_PROTOCOL))
		okey_set_u16(&ret[KEY_MAC_PROTOCOL],
			     ikey_get_u16(&inp[KEY_OOB_PROTOCOL]));

	if (pp_is_valid(inp, KEY_RAW_MAC_SADDR)) {
		int fret;
		if (! pp_is_valid(inp, KEY_RAW_MAC_ADDRLEN))
			return ULOGD_IRET_ERR;
		fret = parse_mac2str(ret,
				     ikey_get_ptr(&inp[KEY_RAW_MAC_SADDR]),
				     KEY_MAC_SADDR,
				     ikey_get_u16(&inp[KEY_RAW_MAC_ADDRLEN]));
		if (fret != ULOGD_IRET_OK)
			return fret;
		/* set MAC type to unknown */
		okey_set_u16(&ret[KEY_MAC_TYPE], ARPHRD_VOID);
	}

	if (pp_is_valid(inp, KEY_RAW_MAC)) {
		if (! pp_is_valid(inp, KEY_RAW_MACLEN))
			return ULOGD_IRET_ERR;
		if (pp_is_valid(inp, KEY_RAW_TYPE)) {
			/* NFLOG with Linux >= 2.6.27 case */
			type = ikey_get_u16(&inp[KEY_RAW_TYPE]);
		} else {
			/* ULOG case, treat ethernet encapsulation */
			if (ikey_get_u16(&inp[KEY_RAW_MACLEN]) == ETH_HLEN)
				type = ARPHRD_ETHER;
			else
				type = ARPHRD_VOID;
		}
		okey_set_u16(&ret[KEY_MAC_TYPE], type);
	}

	switch (type) {
		case ARPHRD_ETHER:
			parse_ethernet(ret, inp);
		default:
			if (!pp_is_valid(inp, KEY_RAW_MAC))
				return ULOGD_IRET_OK;
			/* convert raw header to string */
			return parse_mac2str(ret,
					    ikey_get_ptr(&inp[KEY_RAW_MAC]),
					    KEY_MAC_ADDR,
					    ikey_get_u16(&inp[KEY_RAW_MACLEN]));
	}
	return ULOGD_IRET_OK;
}



static struct ulogd_plugin mac2str_pluging = {
	.name = "HWHDR",
	.input = {
		.keys = mac2str_inp,
		.num_keys = ARRAY_SIZE(mac2str_inp),
		.type = ULOGD_DTYPE_PACKET,
		},
	.output = {
		.keys = mac2str_keys,
		.num_keys = ARRAY_SIZE(mac2str_keys),
		.type = ULOGD_DTYPE_PACKET,
		},
	.interp = &interp_mac2str,
	.version = VERSION,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	ulogd_register_plugin(&mac2str_pluging);
}
