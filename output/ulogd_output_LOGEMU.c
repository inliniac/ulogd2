/* ulogd_LOGEMU.c, Version $Revision$
 *
 * ulogd output target for syslog logging emulation
 *
 * This target produces a file which looks the same like the syslog-entries
 * of the LOG target.
 *
 * (C) 2000-2001 by Harald Welte <laforge@gnumonks.org>
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
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <ulogd/ulogd.h>
#include <ulogd/conffile.h>
#include "../util/printpkt.c"

#ifndef ULOGD_LOGEMU_DEFAULT
#define ULOGD_LOGEMU_DEFAULT	"/var/log/ulogd.syslogemu"
#endif

#ifndef ULOGD_LOGEMU_SYNC_DEFAULT
#define ULOGD_LOGEMU_SYNC_DEFAULT	0
#endif

#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[3]

struct ulogd_key logemu_inp[] = {

};

static struct config_keyset logemu_kset = {
	.num_ces = 2,
	.ces = {
		{
			.key 	 = "file",
			.type	 = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_NONE,
			.u	 = { .string = ULOGD_LOGEMU_DEFAULT },
		},
		{
			.key	 = "sync",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u	 = { .value = ULOGD_LOGEMU_SYNC_DEFAULT },
		},
	},
};

struct logemu_instance {
	struct ulogd_pluginstance upi;
	FILE *of;
};

static int _output_logemu(struct ulogd_pluginstance *upi)
{
	struct logemu_instance *li = (struct logemu_instance *) upi;
	struct ulogd_key *res = upi->input;
	static char buf[4096];

	printpkt_print(res, buf, 1);

	fprintf(li->of, "%s", buf);

	if (upi->configs[1].u.value) 
		fflush(li->of);

	return 0;
}

static void signal_handler_logemu(struct ulogd_pluginstance *pi, int signal)
{
	struct logemu_instance *li = (struct logemu_instance *) pi;

	switch (signal) {
	case SIGHUP:
		ulogd_log(ULOGD_NOTICE, "syslogemu: reopening logfile\n");
		fclose(li->of);
		li->of = fopen(pi->configs[0].u.string, "a");
		if (!li->of) {
			ulogd_log(ULOGD_FATAL, "can't open syslogemu: %s\n",
				  strerror(errno));
			exit(2);
		}
		break;
	default:
		break;
	}
}
		

static struct ulogd_pluginstance *init_logemu(struct ulogd_plugin *pl)
{
	struct logemu_instance *li = malloc(sizeof(*li));

	if (!li)
		return NULL;

	memset(li, 0, sizeof(*li));
	li->upi.plugin = pl;
	/* FIXME: upi->input = NULL; */
	li->upi.output = NULL;

#ifdef DEBUG_LOGEMU
	li->of = stdout;
#else
	li->of = fopen(li->upi.configs[0].u.string, "a");
	if (!li->of) {
		ulogd_log(ULOGD_FATAL, "can't open syslogemu: %s\n", 
			  strerror(errno));
		exit(2);
	}		
#endif
	if (printpkt_init()) {
		ulogd_log(ULOGD_ERROR, "can't resolve all keyhash id's\n");
		exit(1);
	}

	return &li->upi;
}

static int fini_logemu(struct ulogd_pluginstance *pi) {
	struct logemu_instance *li = (struct logemu_instance *) pi;

	if (li->of != stdout)
		fclose(li->of);

	return 0;
}

static struct ulogd_plugin logemu_plugin = { 
	.name = "LOGEMU",
	.input = {
		.keys = &logemu_inp,
		.num_keys = FIXME,
		.type = ULOGD_DTYPE_PACKET,
	},
	.output = {
		.type = ULOGD_DTYPE_SINK,
	},
	.constructor = &init_logemu,
	.destructor = &fini_logemu,
	.interp = &_output_logemu, 
	.signal = &signal_handler_logemu,
	.config_kset = &logemu_kset,
};

void _init(void)
{
	/* FIXME: error handling */
	config_parse_file("LOGEMU", &syslsync_ce);

	register_output(&logemu_op);
}
