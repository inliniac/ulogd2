/* ulogd_LOGEMU.c, Version $Revision$
 *
 * ulogd output target for syslog logging emulation
 *
 * This target produces a file which looks the same like the syslog-entries
 * of the LOG target.
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
	FILE *of;
};

static int _output_logemu(struct ulogd_pluginstance *upi)
{
	struct logemu_instance *li = (struct logemu_instance *) &upi->private;
	struct ulogd_key *res = upi->input;
	static char buf[4096];

	printpkt_print(res, buf, 1);

	fprintf(li->of, "%s", buf);

	if (upi->config_kset->ces[1].u.value) 
		fflush(li->of);

	return 0;
}

static void signal_handler_logemu(struct ulogd_pluginstance *pi, int signal)
{
	struct logemu_instance *li = (struct logemu_instance *) &pi->private;

	switch (signal) {
	case SIGHUP:
		ulogd_log(ULOGD_NOTICE, "syslogemu: reopening logfile\n");
		fclose(li->of);
		li->of = fopen(pi->config_kset->ces[0].u.string, "a");
		if (!li->of) {
			ulogd_log(ULOGD_ERROR, "can't reopen syslogemu: %s\n",
				  strerror(errno));
		}
		break;
	default:
		break;
	}
}
		

static int start_logemu(struct ulogd_pluginstance *pi)
{
	struct logemu_instance *li = (struct logemu_instance *) &pi->private;

#ifdef DEBUG_LOGEMU
	li->of = stdout;
#else
	li->of = fopen(pi->config_kset->ces[0].u.string, "a");
	if (!li->of) {
		ulogd_log(ULOGD_FATAL, "can't open syslogemu: %s\n", 
			  strerror(errno));
		return errno;
	}		
#endif
	if (printpkt_init()) {
		ulogd_log(ULOGD_ERROR, "can't resolve all keyhash id's\n");
		return -EINVAL;
	}

	return 0;
}

static int fini_logemu(struct ulogd_pluginstance *pi) {
	struct logemu_instance *li = (struct logemu_instance *) &pi->private;

	if (li->of != stdout)
		fclose(li->of);

	return 0;
}

static int configure_logemu(struct ulogd_pluginstance *pi,
			    struct ulogd_pluginstance_stack *stack)
{
	/* FIXME: error handling */
	config_parse_file(pi->id, &logemu_kset);

	return 0;
}

static struct ulogd_plugin logemu_plugin = { 
	.name = "LOGEMU",
	.input = {
		.keys = printpkt_keys,
		.num_keys = ARRAY_SIZE(printpkt_keys),
		.type = ULOGD_DTYPE_PACKET,
	},
	.output = {
		.type = ULOGD_DTYPE_SINK,
	},
	.config_kset 	= &logemu_kset,
	.priv_size 	= sizeof(struct logemu_instance),

	.configure	= &configure_logemu,
	.start	 	= &start_logemu,
	.stop	 	= &fini_logemu,

	.interp 	= &_output_logemu, 
	.signal 	= &signal_handler_logemu,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	ulogd_register_plugin(&logemu_plugin);
}
