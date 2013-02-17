/* ulogd_GRAPHITE.c
 *
 * ulogd output target to feed data to a graphite system
 *
 * (C) 2012 by Eric Leblond <eric@regit.org>
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
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ulogd/ulogd.h>
#include <ulogd/conffile.h>


enum {
	KEY_SUM_NAME,
	KEY_SUM_PKTS,
	KEY_SUM_BYTES,
	KEY_OOB_TIME_SEC,
};


static struct ulogd_key graphite_inp[] = {
	[KEY_SUM_NAME] = {
		.type	= ULOGD_RET_STRING,
		.name	= "sum.name",
	},
	[KEY_SUM_PKTS] = {
		.type	= ULOGD_RET_UINT64,
		.name	= "sum.pkts",
	},
	[KEY_SUM_BYTES] = {
		.type	= ULOGD_RET_UINT64,
		.name	= "sum.bytes",
	},
	[KEY_OOB_TIME_SEC] = {
		.type = ULOGD_RET_UINT32,
		.name = "oob.time.sec",
	},
};


static struct config_keyset graphite_kset = {
	.num_ces = 3,
	.ces = {
		{
			.key = "host",
			.type = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_NONE,
		},
		{
			.key = "port",
			.type = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_NONE,
		},
		{
			.key = "prefix",
			.type = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_NONE,
		},
	},
};

#define host_ce(x)	(x->ces[0])
#define port_ce(x)	(x->ces[1])
#define prefix_ce(x)	(x->ces[2])

struct graphite_instance {
	int sck;
};

static int _connect_graphite(struct ulogd_pluginstance *pi)
{
	struct graphite_instance *li = (struct graphite_instance *) &pi->private;
	char *host;
	char * port;
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int sfd, s;

	ulogd_log(ULOGD_DEBUG, "connecting to graphite\n");

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = 0;
	hints.ai_protocol = 0;

	host = host_ce(pi->config_kset).u.string;
	port = port_ce(pi->config_kset).u.string;
	s = getaddrinfo(host, port, &hints, &result);
	if (s != 0) {
		ulogd_log(ULOGD_ERROR, "getaddrinfo: %s\n", gai_strerror(s));
		return -1;
	}

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		int on = 1;

		sfd = socket(rp->ai_family, rp->ai_socktype,
				rp->ai_protocol);
		if (sfd == -1)
			continue;

		setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR,
			   (char *) &on, sizeof(on));

		if (connect(sfd, rp->ai_addr, rp->ai_addrlen) != -1)
			break;

		close(sfd);
	}

	freeaddrinfo(result);

	if (rp == NULL) {
		ulogd_log(ULOGD_ERROR, "Could not connect\n");
		return -1;
	}

	li->sck = sfd;

	return 0;
}

static int _output_graphite(struct ulogd_pluginstance *upi)
{
	struct graphite_instance *li = (struct graphite_instance *) &upi->private;
	struct ulogd_key *inp = upi->input.keys;
	static char buf[256];
	int ret;

	time_t now;
	int msg_size = 0;

	if (ikey_get_u32(&inp[KEY_OOB_TIME_SEC]))
		now = (time_t) ikey_get_u32(&inp[KEY_OOB_TIME_SEC]);
	else
		now = time(NULL);

	msg_size = snprintf(buf, sizeof(buf), "%s.%s.pkts %" PRIu64
			    " %" PRIu64 "\n%s.%s.bytes %" PRIu64 " %" PRIu64 "\n",
		 prefix_ce(upi->config_kset).u.string,
		 (char *)ikey_get_ptr(&inp[KEY_SUM_NAME]),
		 ikey_get_u64(&inp[KEY_SUM_PKTS]),
		 (uint64_t) now,
		 prefix_ce(upi->config_kset).u.string,
		 (char *)ikey_get_ptr(&inp[KEY_SUM_NAME]),
		 ikey_get_u64(&inp[KEY_SUM_BYTES]),
		 (uint64_t) now
		 );
	if (msg_size == -1) {
		ulogd_log(ULOGD_ERROR, "Could not create message\n");
		return ULOGD_IRET_ERR;
	}
	ret = send(li->sck, buf, msg_size, MSG_NOSIGNAL);
	if (ret != msg_size) {
		ulogd_log(ULOGD_ERROR, "Failure sending message\n");
		if (ret == -1) {
			return _connect_graphite(upi);
		}
	}

	return ULOGD_IRET_OK;
}

static int start_graphite(struct ulogd_pluginstance *pi)
{
	char *host;
	char *port;

	ulogd_log(ULOGD_DEBUG, "starting graphite\n");

	host = host_ce(pi->config_kset).u.string;
	if (host == NULL)
		return -1;
	port = port_ce(pi->config_kset).u.string;
	if (port == NULL)
		return -1;
	return _connect_graphite(pi);
}

static int fini_graphite(struct ulogd_pluginstance *pi) {
	struct graphite_instance *li = (struct graphite_instance *) &pi->private;

	close(li->sck);
	li->sck = 0;

	return 0;
}

static int configure_graphite(struct ulogd_pluginstance *pi,
			    struct ulogd_pluginstance_stack *stack)
{
	ulogd_log(ULOGD_DEBUG, "parsing config file section %s\n", pi->id);
	return config_parse_file(pi->id, pi->config_kset);
}

static struct ulogd_plugin graphite_plugin = {
	.name = "GRAPHITE",
	.input = {
		.keys = graphite_inp,
		.num_keys = ARRAY_SIZE(graphite_inp),
		.type = ULOGD_DTYPE_SUM,
	},
	.output = {
		.type = ULOGD_DTYPE_SINK,
	},
	.config_kset 	= &graphite_kset,
	.priv_size 	= sizeof(struct graphite_instance),

	.configure	= &configure_graphite,
	.start	 	= &start_graphite,
	.stop	 	= &fini_graphite,

	.interp 	= &_output_graphite,
	.version	= VERSION,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	ulogd_register_plugin(&graphite_plugin);
}
