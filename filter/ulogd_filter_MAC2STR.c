/* ulogd_filter_MAC2STR.c, Version $Revision: 1500 $
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
#include <ulogd/ulogd.h>

#define IPADDR_LENGTH 128

enum input_keys {
	KEY_RAW_MAC,
	KEY_RAW_MACLEN,
};

enum output_keys {
	KEY_MAC_SADDR,
};

static struct ulogd_key mac2str_inp[] = {
	[KEY_RAW_MAC] = {
		.type = ULOGD_RET_RAW,
		.flags = ULOGD_RETF_NONE,
		.name = "raw.mac",
	},
	[KEY_RAW_MACLEN] = { 
		.type = ULOGD_RET_UINT16, 
		.flags = ULOGD_RETF_NONE, 
		.name = "raw.mac_len", 
	},

};

static struct ulogd_key mac2str_keys[] = {
	{
		.type = ULOGD_RET_STRING,
		.flags = ULOGD_RETF_FREE,
		.name = "mac.saddr.str",
	},
};

static int interp_mac2str(struct ulogd_pluginstance *pi)
{
	struct ulogd_key *ret = pi->output.keys;
	struct ulogd_key *inp = pi->input.keys;

	if (pp_is_valid(inp, KEY_RAW_MAC)) {
		unsigned char *mac = (unsigned char *) GET_VALUE(inp, KEY_RAW_MAC).ptr;
		int len = GET_VALUE(inp, KEY_RAW_MACLEN).ui16;
		char *mac_str = calloc(len/sizeof(char)*3, sizeof(char));
		char *buf_cur = mac_str;
		int i;
		
		if (mac_str == NULL)
			return ULOGD_IRET_ERR;

		for (i = 0; i < len; i++)
			buf_cur += sprintf(buf_cur, "%02x%c", mac[i],
					   i == len - 1 ? 0 : ':');

		ret[KEY_MAC_SADDR].u.value.ptr = mac_str;
		ret[KEY_MAC_SADDR].flags |= ULOGD_RETF_VALID;
	}

	return ULOGD_IRET_OK;
}

static struct ulogd_plugin mac2str_pluging = {
	.name = "MAC2STR",
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
