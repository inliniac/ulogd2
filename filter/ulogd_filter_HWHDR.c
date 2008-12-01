/* ulogd_filter_HWHDR.c, Version $Revision: 1500 $
 *
 * ulogd interpreter plugin for HWMAC
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
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <ulogd/ulogd.h>

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
	KEY_MAC_DADDR,
	KEY_MAC_ADDR,
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
		.flags = ULOGD_RETF_FREE,
		.name = "mac.saddr.str",
	},
	[KEY_MAC_DADDR] = {
		.type = ULOGD_RET_STRING,
		.flags = ULOGD_RETF_FREE,
		.name = "mac.daddr.str",
	},
	[KEY_MAC_ADDR] = {
		.type = ULOGD_RET_STRING,
		.flags = ULOGD_RETF_FREE,
		.name = "mac.str",
	},
};

static int parse_mac2str(struct ulogd_key *ret, unsigned char *mac,
			 int okey, int len)
{
	char *mac_str;
	char *buf_cur;
	int i;

	if (len > 0)
		mac_str = calloc(len/sizeof(char)*3, sizeof(char));
	else
		mac_str = strdup("");

	if (mac_str == NULL)
		return ULOGD_IRET_ERR;

	buf_cur = mac_str;
	for (i = 0; i < len; i++)
		buf_cur += sprintf(buf_cur, "%02x%c", mac[i],
				i == len - 1 ? 0 : ':');

	ret[okey].u.value.ptr = mac_str;
	ret[okey].flags |= ULOGD_RETF_VALID;

	return ULOGD_IRET_OK;
}

static int parse_ethernet(struct ulogd_key *ret, struct ulogd_key *inp)
{
	int fret;
	if (!pp_is_valid(inp, KEY_RAW_MAC_SADDR)) {
		fret = parse_mac2str(ret, 
				     GET_VALUE(inp, KEY_RAW_MAC).ptr
					+ ETH_ALEN,
				     KEY_MAC_SADDR, ETH_ALEN);
		if (fret != ULOGD_IRET_OK)
			return fret;
	}
	fret = parse_mac2str(ret, GET_VALUE(inp, KEY_RAW_MAC).ptr,
			     KEY_MAC_DADDR, ETH_ALEN);
	if (fret != ULOGD_IRET_OK)
		return fret;

	ret[KEY_MAC_PROTOCOL].u.value.ui16 =
		ntohs(*(u_int16_t *) (GET_VALUE(inp, KEY_RAW_MAC).ptr
					+ 2 * ETH_ALEN));
	ret[KEY_MAC_PROTOCOL].flags |= ULOGD_RETF_VALID;

	return ULOGD_IRET_OK;
}

static int interp_mac2str(struct ulogd_pluginstance *pi)
{
	struct ulogd_key *ret = pi->output.keys;
	struct ulogd_key *inp = pi->input.keys;
	u_int16_t type = 0;

	if (pp_is_valid(inp, KEY_OOB_PROTOCOL)) {
		ret[KEY_MAC_PROTOCOL].u.value.ui16 =
			GET_VALUE(inp, KEY_OOB_PROTOCOL).ui16;
		ret[KEY_MAC_PROTOCOL].flags |= ULOGD_RETF_VALID;
	}

	if (pp_is_valid(inp, KEY_RAW_MAC_SADDR)) {
		int fret;
		fret = parse_mac2str(ret,
				     GET_VALUE(inp, KEY_RAW_MAC_SADDR).ptr,
				     KEY_MAC_SADDR,
				     GET_VALUE(inp, KEY_RAW_MAC_ADDRLEN).ui16);
		if (fret != ULOGD_IRET_OK)
			return fret;
	}

	if (pp_is_valid(inp, KEY_RAW_MAC)) {
		if (GET_VALUE(inp, KEY_RAW_MAC_ADDRLEN).ui16 == ETH_ALEN) {
			ret[KEY_MAC_TYPE].u.value.ui16 = ARPHRD_ETHER;
			ret[KEY_MAC_TYPE].flags |= ULOGD_RETF_VALID;
		} else {
			ret[KEY_MAC_TYPE].u.value.ui16 = ARPHRD_VOID;
			ret[KEY_MAC_TYPE].flags |= ULOGD_RETF_VALID;
		}
		return ULOGD_IRET_OK;
	}

	if (pp_is_valid(inp, KEY_RAW_TYPE)) {
		/* NFLOG with Linux >= 2.6.27 case */
		ret[KEY_MAC_TYPE].u.value.ui16 = type =
			GET_VALUE(inp, KEY_RAW_TYPE).ui16;
		ret[KEY_MAC_TYPE].flags |= ULOGD_RETF_VALID;
	} else {
		/* ULOG case, treat ethernet encapsulation */
		if (GET_VALUE(inp, KEY_RAW_MACLEN).ui16 == ETH_HLEN) {
			ret[KEY_MAC_TYPE].u.value.ui16 = type = ARPHRD_ETHER;
			ret[KEY_MAC_TYPE].flags |= ULOGD_RETF_VALID;
		} else {
			ret[KEY_MAC_TYPE].u.value.ui16 = type = ARPHRD_VOID;
			ret[KEY_MAC_TYPE].flags |= ULOGD_RETF_VALID;
		}
	}

	switch (type) {
		case ARPHRD_ETHER:
			parse_ethernet(ret, inp);
		default:
			/* convert raw header to string */
			return parse_mac2str(ret,
					     GET_VALUE(inp, KEY_RAW_MAC).ptr,
					     KEY_MAC_ADDR,
					     GET_VALUE(inp,
						     KEY_RAW_MACLEN).ui16);
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
	.version = ULOGD_VERSION,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	ulogd_register_plugin(&mac2str_pluging);
}
