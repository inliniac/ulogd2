/* ulogd_output_IPFIX.c, Version $Revision: 1628 $
 *
 * ulogd output plugin for IPFIX
 *
 * This target produces a file which looks the same like the syslog-entries
 * of the LOG target.
 *
 * (C) 2005 by Harald Welte <laforge@gnumonks.org>
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
 * $Id: ulogd_output_LOGEMU.c 1628 2005-11-04 15:23:12Z laforge $
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <ulogd/ulogd.h>
#include <ulogd/conffile.h>
#include <ulogd/ipfix_protocol.h>

#define IPFIX_DEFAULT_TCPUDP_PORT	4739

static struct config_keyset ipfix_kset = {
	.num_ces = 3,
	.ces = {
		{
			.key 	 = "host",
			.type	 = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_NONE,
		},
		{
			.key	 = "port",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u	 = { .value = IPFIX_DEFAULT_TCPUDP_PORT },
		},
		{
			.key	 = "protocol",
			.type	 = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_NONE,
			.u	= { .string = "udp" },
		},
	},
};

struct ipfix_instance {
	int fd;		/* socket that we use for sending IPFIX data */

	struct {
		char *buf;
		unsigned int len;
	} template;
};


/* Build the IPFIX template from the input keys */
static int build_template(struct ulogd_pluginstance *upi)
{
	struct ipfix_instance *ii = (struct ipfix_instance *) &upi->private;


}

static int _output_ipfix(struct ulogd_pluginstance *upi)
{
	struct ipfix_instance *ii = (struct ipfix_instance *) &upi->private;
	struct ulogd_key *res = upi->input;
	static char buf[4096];

	printpkt_print(res, buf, 1);

	fprintf(li->of, "%s", buf);

	if (upi->config_kset->ces[1].u.value) 
		fflush(li->of);

	return 0;
}

static void signal_handler_ipfix(struct ulogd_pluginstance *pi, int signal)
{
	struct ipfix_instance *li = (struct ipfix_instance *) &pi->private;

	switch (signal) {
	case SIGHUP:
		ulogd_log(ULOGD_NOTICE, "sysipfix: reopening logfile\n");
		fclose(li->of);
		li->of = fopen(pi->config_kset->ces[0].u.string, "a");
		if (!li->of) {
			ulogd_log(ULOGD_ERROR, "can't reopen sysipfix: %s\n",
				  strerror(errno));
		}
		break;
	default:
		break;
	}
}
		

static int start_ipfix(struct ulogd_pluginstance *pi)
{
	struct ipfix_instance *li = (struct ipfix_instance *) &pi->private;

	ulogd_log(ULOGD_DEBUG, "starting ipfix\n");

#ifdef DEBUG_LOGEMU
	li->of = stdout;
#else
	ulogd_log(ULOGD_DEBUG, "opening file: %s\n",
		  pi->config_kset->ces[0].u.string);
	li->of = fopen(pi->config_kset->ces[0].u.string, "a");
	if (!li->of) {
		ulogd_log(ULOGD_FATAL, "can't open sysipfix: %s\n", 
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

static int fini_ipfix(struct ulogd_pluginstance *pi) {
	struct ipfix_instance *li = (struct ipfix_instance *) &pi->private;

	if (li->of != stdout)
		fclose(li->of);

	return 0;
}

static int configure_ipfix(struct ulogd_pluginstance *pi,
			    struct ulogd_pluginstance_stack *stack)
{
	/* FIXME: error handling */
	ulogd_log(ULOGD_DEBUG, "parsing config file section %s\n", pi->id);
	config_parse_file(pi->id, pi->config_kset);

	return 0;
}

static struct ulogd_plugin ipfix_plugin = { 
	.name = "IPFIX",
	.input = {
		.keys = printpkt_keys,
		.num_keys = ARRAY_SIZE(printpkt_keys),
		.type = ULOGD_DTYPE_PACKET,
	},
	.output = {
		.type = ULOGD_DTYPE_SINK,
	},
	.config_kset 	= &ipfix_kset,
	.priv_size 	= sizeof(struct ipfix_instance),

	.configure	= &configure_ipfix,
	.start	 	= &start_ipfix,
	.stop	 	= &fini_ipfix,

	.interp 	= &_output_ipfix, 
	.signal 	= &signal_handler_ipfix,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	ulogd_register_plugin(&ipfix_plugin);
}
