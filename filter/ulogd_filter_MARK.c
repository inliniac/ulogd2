/* ulogd_filter_MARK.c
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
 */

#include <stdio.h>
#include <ulogd/ulogd.h>

enum mark_kset {
	MARK_MARK,
	MARK_MASK,
};

static struct config_keyset libulog_kset = {
	.num_ces = 2,
	.ces = {
		[MARK_MARK] = {
			.key 	 = "mark",
			.type 	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 0,
		},
		[MARK_MASK] = {
			.key 	 = "mask",
			.type 	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 0xffffffff,
		},

	}
};
	
enum input_keys {
	KEY_CT_MARK,
	KEY_OOB_MARK,
	MAX_KEY = KEY_OOB_MARK,
};

static struct ulogd_key mark_inp[] = {
	[KEY_CT_MARK] = {
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE|ULOGD_KEYF_OPTIONAL,
		.name = "ct.mark",
	},
	[KEY_OOB_MARK] = {
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE|ULOGD_KEYF_OPTIONAL,
		.name = "oob.mark",
	},
};

static int interp_mark(struct ulogd_pluginstance *pi)
{
	struct ulogd_key *inp = pi->input.keys;
	if (pp_is_valid(inp, KEY_CT_MARK)) {
		if ((ikey_get_u32(&inp[KEY_CT_MARK]) &
			pi->config_kset->ces[MARK_MASK].u.value) !=
			(u_int32_t) pi->config_kset->ces[MARK_MARK].u.value
		   ) {
			return ULOGD_IRET_STOP;
		}
	} else if (pp_is_valid(inp, KEY_OOB_MARK)) {
		if ((ikey_get_u32(&inp[KEY_OOB_MARK]) &
			pi->config_kset->ces[MARK_MASK].u.value) !=
			(u_int32_t) pi->config_kset->ces[MARK_MARK].u.value
		   ) {
			return ULOGD_IRET_STOP;
		}
	}
	return ULOGD_IRET_OK;	
}

static int configure(struct ulogd_pluginstance *upi,
		     struct ulogd_pluginstance_stack *stack)
{
	ulogd_log(ULOGD_DEBUG, "parsing config file section `%s', "
		  "plugin `%s'\n", upi->id, upi->plugin->name);

	config_parse_file(upi->id, upi->config_kset);
	return 0;
}

static struct ulogd_plugin mark_pluging = {
	.name = "MARK",
	.input = {
		.keys = mark_inp,
		.num_keys = ARRAY_SIZE(mark_inp),
		.type = ULOGD_DTYPE_PACKET | ULOGD_DTYPE_FLOW,
		},
	.output = {
		.type = ULOGD_DTYPE_PACKET | ULOGD_DTYPE_FLOW,
		},
	.interp = &interp_mark,
	.config_kset = &libulog_kset,
	.configure = &configure,
	.version = VERSION,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	ulogd_register_plugin(&mark_pluging);
}
