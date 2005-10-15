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
	static FILE *of = NULL;
};

static int oprint_interp(struct ulogd_pluginstance *instance)
{
	ulog_iret_t *ret = instance->input.keys;
	
	fprintf(of, "===>PACKET BOUNDARY\n");
	for (ret = res; ret; ret = ret->cur_next) {
		fprintf(of,"%s=", ret->key);
		switch (ret->type) {
			case ULOGD_RET_STRING:
				fprintf(of, "%s\n", (char *) ret->value.ptr);
				break;
			case ULOGD_RET_BOOL:
			case ULOGD_RET_INT8:
			case ULOGD_RET_INT16:
			case ULOGD_RET_INT32:
				fprintf(of, "%d\n", ret->value.i32);
				break;
			case ULOGD_RET_UINT8:
			case ULOGD_RET_UINT16:
			case ULOGD_RET_UINT32:
				fprintf(of, "%u\n", ret->value.ui32);
				break;
			case ULOGD_RET_IPADDR:
				fprintf(of, "%u.%u.%u.%u\n", 
					HIPQUAD(ret->value.ui32));
				break;
			case ULOGD_RET_NONE:
				fprintf(of, "<none>");
				break;
		}
	}
	return 0;
}

static struct config_entry outf_ce = { 
	.key = "file", 
	.type = CONFIG_TYPE_STRING, 
	.options = CONFIG_OPT_NONE,
	.u.string = ULOGD_OPRINT_DEFAULT
};

static void sighup_handler_print(int signal)
{

	switch (signal) {
	case SIGHUP:
		ulogd_log(ULOGD_NOTICE, "PKTLOG: reopening logfile\n");
		fclose(of);
		of = fopen(outf_ce.u.string, "a");
		if (!of) {
			ulogd_log(ULOGD_FATAL, "can't open PKTLOG: %s\n",
				strerror(errno));
			exit(2);
		}
		break;
	default:
		break;
	}
}

static struct ulogd_pluginstance *oprint_init(struct ulogd_plugin *pl)
{
	struct oprint_priv *op;
	struct ulogd_pluginstance *opi = malloc(sizeof(*opi)+sizeof(*op));

	if (!opi)
		return NULL;

	op = (struct oprint_priv *) opi->private;
	opi->plugin = pl;
	/* FIXME: opi->input */
	opi->output = NULL;

#ifdef DEBUG
	op->of = stdout;
#else
	config_parse_file("OPRINT", &outf_ce);

	op->of = fopen(outf_ce.u.string, "a");
	if (!op->of) {
		ulogd_log(ULOGD_FATAL, "can't open PKTLOG: %s\n", 
			strerror(errno));
		exit(2);
	}		
#endif
	return opi;
}

static int oprint_fini(struct ulogd_pluginstance *pi)
{
	struct oprint_priv *op = (struct oprint_priv *) pi->priv;

	if (op->of != stdout)
		fclose(op->of);

	return 1;
}

static struct ulogd_plugin oprint_plugin = {
	.name = "OPRINT", 
	.input = {
			.type = ULOGD_DTYPE_PKT,
		},
	.output = {
			.type = ULOGD_DTYPE_SINK,
		},
	.interp = &oprint_interp,
	.constructor = &oprint_init,
	.destructor = &oprint_fini,
	.signal = &sighup_handler_print,
	.configs = &outf_ce,
	.num_configs = 1,
};

void _init(void)
{
	ulogd_register_output(&oprint_plugin);
}
