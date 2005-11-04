/* ulogd_MAC.c, Version $Revision$
 *
 * ulogd output target for logging to a file 
 *
 * (C) 2000-2005 by Harald Welte <laforge@gnumonks.org>
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
 * $Id$
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ulogd/ulogd.h>
#include <ulogd/conffile.h>

#ifndef ULOGD_OPRINT_DEFAULT
#define ULOGD_OPRINT_DEFAULT	"/var/log/ulogd.pktlog"
#endif

#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[3]

#define HIPQUAD(addr) \
        ((unsigned char *)&addr)[3], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[0]

struct oprint_priv {
	FILE *of;
};

static int oprint_interp(struct ulogd_pluginstance *upi)
{
	struct oprint_priv *opi = (struct oprint_priv *) &upi->private;
	unsigned int i;
	
	fprintf(opi->of, "===>PACKET BOUNDARY\n");
	for (i = 0; i < upi->plugin->input.num_keys; i++) {
		struct ulogd_key *ret = upi->input[i].u.source;

		if (!IS_VALID(*ret))
			continue;

		fprintf(opi->of,"%s=", ret->name);
		switch (ret->type) {
			case ULOGD_RET_STRING:
				fprintf(opi->of, "%s\n",
					(char *) ret->u.value.ptr);
				break;
			case ULOGD_RET_BOOL:
			case ULOGD_RET_INT8:
			case ULOGD_RET_INT16:
			case ULOGD_RET_INT32:
				fprintf(opi->of, "%d\n", ret->u.value.i32);
				break;
			case ULOGD_RET_UINT8:
			case ULOGD_RET_UINT16:
			case ULOGD_RET_UINT32:
				fprintf(opi->of, "%u\n", ret->u.value.ui32);
				break;
			case ULOGD_RET_IPADDR:
				fprintf(opi->of, "%u.%u.%u.%u\n", 
					HIPQUAD(ret->u.value.ui32));
				break;
			case ULOGD_RET_NONE:
				fprintf(opi->of, "<none>");
				break;
		}
	}
	return 0;
}

static struct config_keyset oprint_kset = {
	.num_ces = 1,
	.ces = {
		{
		.key = "file", 
		.type = CONFIG_TYPE_STRING, 
		.options = CONFIG_OPT_NONE,
		.u = {.string = ULOGD_OPRINT_DEFAULT },
		},
	},
};

static void sighup_handler_print(struct ulogd_pluginstance *upi, int signal)
{
	struct oprint_priv *oi = (struct oprint_priv *) &upi->private;

	switch (signal) {
	case SIGHUP:
		ulogd_log(ULOGD_NOTICE, "OPRINT: reopening logfile\n");
		fclose(oi->of);
		oi->of = fopen(upi->config_kset->ces[0].u.string, "a");
		if (!oi->of) {
			ulogd_log(ULOGD_ERROR, "can't open PKTLOG: %s\n",
				strerror(errno));
		}
		break;
	default:
		break;
	}
}

static int oprint_configure(struct ulogd_pluginstance *upi,
			    struct ulogd_pluginstance_stack *stack)
{
	struct ulogd_pluginstance *pi_cur;
	unsigned int num_keys = 0;
	unsigned int index = 0;

	/* ok, this is a bit tricky, and probably requires some documentation.
	 * Since we are a output plugin (SINK), we can only be the last one
	 * in the stack.  Therefore, all other (input/filter) plugins, area
	 * already linked into the stack.  This means, we can iterate over them,
	 * get a list of all the keys, and create one input key for every output
	 * key that any of the upstream plugins provide.  By the time we resolve
	 * the inter-key pointers, everything will work as expected. */

	/* first pass: count keys */
	list_for_each_entry(pi_cur, &stack->list, list) {
		ulogd_log(ULOGD_DEBUG, "iterating over pluginstance '%s'\n",
			  pi_cur->id);
		num_keys += pi_cur->plugin->output.num_keys;
	}

	ulogd_log(ULOGD_DEBUG, "allocating %u input keys\n", num_keys);
	upi->input = malloc(sizeof(struct ulogd_key) * num_keys);
	if (!upi->input)
		return -ENOMEM;

	/* second pass: copy key names */
	list_for_each_entry(pi_cur, &stack->list, list) {
		struct ulogd_key *cur;
		int i;

		for (i = 0; i < pi_cur->plugin->output.num_keys; i++)
			upi->input[index++] = pi_cur->output[i];
	}

	config_parse_file(upi->id, upi->config_kset);

	/* FIXME: the count needs to be per-instance */
	upi->plugin->input.num_keys = num_keys;

	return 0;
}

static int oprint_init(struct ulogd_pluginstance *upi)
{
	struct oprint_priv *op = (struct oprint_priv *) &upi->private;

	op->of = fopen(upi->config_kset->ces[0].u.string, "a");
	if (!op->of) {
		ulogd_log(ULOGD_FATAL, "can't open PKTLOG: %s\n", 
			strerror(errno));
		return -1;
	}		
	return 0;
}

static int oprint_fini(struct ulogd_pluginstance *pi)
{
	struct oprint_priv *op = (struct oprint_priv *) &pi->private;

	if (op->of != stdout)
		fclose(op->of);

	return 0;
}

static struct ulogd_plugin oprint_plugin = {
	.name = "OPRINT", 
	.input = {
			.type = ULOGD_DTYPE_PACKET,
		},
	.output = {
			.type = ULOGD_DTYPE_SINK,
		},
	.configure = &oprint_configure,
	.interp	= &oprint_interp,
	.start 	= &oprint_init,
	.stop	= &oprint_fini,
	.signal = &sighup_handler_print,
	.config_kset = &oprint_kset,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	ulogd_register_plugin(&oprint_plugin);
}
