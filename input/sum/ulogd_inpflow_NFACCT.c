/* ulogd_input_NFACCT.c
 *
 * ulogd input plugin for nfacct
 *
 * (C) 2012 by Pablo Neira Ayuso <pablo@netfilter.org>
 * (C) 2012 by Intra2net AG <http://www.intra2net.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <sys/time.h>
#include <time.h>
#include <netinet/in.h>

#include <ulogd/ulogd.h>
#include <ulogd/timer.h>

#include <libmnl/libmnl.h>
#include <libnetfilter_acct/libnetfilter_acct.h>

struct nfacct_pluginstance {
	struct mnl_socket	*nl;
	uint32_t		portid;
	uint32_t		seq;
	struct ulogd_fd		ufd;
	struct ulogd_timer	timer;
	struct timeval tv;
};

static struct config_keyset nfacct_kset = {
	.ces = {
		{
			.key	 = "pollinterval",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 0,
		},
		{
			.key	 = "zerocounter",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 1,
		},
		{
			.key	 = "timestamp",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 0,
		}
	},
	.num_ces = 3,
};
#define pollint_ce(x)	(x->ces[0])
#define zerocounter_ce(x) (x->ces[1])
#define timestamp_ce(x) (x->ces[2])

enum ulogd_nfacct_keys {
	ULOGD_NFACCT_NAME,
	ULOGD_NFACCT_PKTS,
	ULOGD_NFACCT_BYTES,
	ULOGD_NFACCT_RAW,
	ULOGD_NFACCT_TIME_SEC,
	ULOGD_NFACCT_TIME_USEC,
};

static struct ulogd_key nfacct_okeys[] = {
	[ULOGD_NFACCT_NAME] = {
		.type	= ULOGD_RET_STRING,
		.flags	= ULOGD_RETF_NONE,
		.name	= "sum.name",
	},
	[ULOGD_NFACCT_PKTS] = {
		.type	= ULOGD_RET_UINT64,
		.flags	= ULOGD_RETF_NONE,
		.name	= "sum.pkts",
	},
	[ULOGD_NFACCT_BYTES] = {
		.type	= ULOGD_RET_UINT64,
		.flags	= ULOGD_RETF_NONE,
		.name	= "sum.bytes",
	},
	[ULOGD_NFACCT_RAW] = {
		.type	= ULOGD_RET_RAW,
		.flags	= ULOGD_RETF_NONE,
		.name	= "sum",
	},
	[ULOGD_NFACCT_TIME_SEC] = {
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.time.sec",
	},
	[ULOGD_NFACCT_TIME_USEC] = {
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.time.usec",
	},
};

static void
propagate_nfacct(struct ulogd_pluginstance *upi, struct nfacct *nfacct)
{
	struct ulogd_key *ret = upi->output.keys;
	struct nfacct_pluginstance *cpi = (struct nfacct_pluginstance *) upi->private;

	okey_set_ptr(&ret[ULOGD_NFACCT_NAME],
			(void *)nfacct_attr_get_str(nfacct, NFACCT_ATTR_NAME));
	okey_set_u64(&ret[ULOGD_NFACCT_PKTS],
			nfacct_attr_get_u64(nfacct, NFACCT_ATTR_PKTS));
	okey_set_u64(&ret[ULOGD_NFACCT_BYTES],
			nfacct_attr_get_u64(nfacct, NFACCT_ATTR_BYTES));
	okey_set_ptr(&ret[ULOGD_NFACCT_RAW], nfacct);

	if (timestamp_ce(upi->config_kset).u.value != 0) {
		okey_set_u32(&ret[ULOGD_NFACCT_TIME_SEC], cpi->tv.tv_sec);
		okey_set_u32(&ret[ULOGD_NFACCT_TIME_USEC], cpi->tv.tv_usec);
	}

	ulogd_propagate_results(upi);
}

static void
do_propagate_nfacct(struct ulogd_pluginstance *upi, struct nfacct *nfacct)
{
	struct ulogd_pluginstance *npi = NULL;

	llist_for_each_entry(npi, &upi->plist, plist)
		propagate_nfacct(npi, nfacct);

	propagate_nfacct(upi, nfacct);

	nfacct_free(nfacct);
}

static int nfacct_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nfacct *nfacct;
	struct ulogd_pluginstance *upi = data;

	nfacct = nfacct_alloc();
	if (nfacct == NULL) {
		ulogd_log(ULOGD_ERROR, "OOM");
		goto err;
	}

	if (nfacct_nlmsg_parse_payload(nlh, nfacct) < 0) {
		ulogd_log(ULOGD_ERROR, "Error parsing nfacct message");
		goto err;
	}

	do_propagate_nfacct(upi, nfacct);

err:
	return MNL_CB_OK;
}

static int nfacct_read_cb(int fd, unsigned int what, void *param)
{
	int ret;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct ulogd_pluginstance *upi = param;
	struct nfacct_pluginstance *cpi =
		(struct nfacct_pluginstance *) upi->private;

	if (!(what & ULOGD_FD_READ))
		return 0;

	ret = mnl_socket_recvfrom(cpi->nl, buf, sizeof(buf));
	if (ret > 0) {
		ret = mnl_cb_run(buf, ret, cpi->seq,
				 cpi->portid, nfacct_cb, upi);
	}
	return ret;
}

static int nfacct_send_request(struct ulogd_pluginstance *upi)
{
	struct nfacct_pluginstance *cpi =
		(struct nfacct_pluginstance *)upi->private;
	struct nlmsghdr *nlh;
	char buf[MNL_SOCKET_BUFFER_SIZE];
	int flushctr;

	if (zerocounter_ce(upi->config_kset).u.value != 0)
		flushctr = NFNL_MSG_ACCT_GET_CTRZERO;
	else
		flushctr = NFNL_MSG_ACCT_GET;

	cpi->seq = time(NULL);
	nlh = nfacct_nlmsg_build_hdr(buf, flushctr, NLM_F_DUMP, cpi->seq);

	if (mnl_socket_sendto(cpi->nl, nlh, nlh->nlmsg_len) < 0) {
		ulogd_log(ULOGD_ERROR, "Cannot send netlink message\n");
		return -1;
	}
	if (timestamp_ce(upi->config_kset).u.value != 0) {
		/* Compute time of query */
		gettimeofday(&cpi->tv, NULL);
	}
	return 0;
}

static void polling_timer_cb(struct ulogd_timer *t, void *data)
{
	struct ulogd_pluginstance *upi = data;
	struct nfacct_pluginstance *cpi =
		(struct nfacct_pluginstance *)upi->private;

	nfacct_send_request(upi);

	ulogd_add_timer(&cpi->timer, pollint_ce(upi->config_kset).u.value);
}

static int configure_nfacct(struct ulogd_pluginstance *upi,
			    struct ulogd_pluginstance_stack *stack)
{
	int ret;

	ret = config_parse_file(upi->id, upi->config_kset);
	if (ret < 0)
		return ret;

	if (pollint_ce(upi->config_kset).u.value <= 0) {
		ulogd_log(ULOGD_FATAL, "You have to set pollint\n");
		return -1;
	}
	return 0;
}

static int constructor_nfacct(struct ulogd_pluginstance *upi)
{
	struct nfacct_pluginstance *cpi =
		(struct nfacct_pluginstance *)upi->private;

	if (pollint_ce(upi->config_kset).u.value == 0)
		return -1;

	cpi->nl = mnl_socket_open(NETLINK_NETFILTER);
	if (cpi->nl == NULL) {
		ulogd_log(ULOGD_FATAL, "cannot open netlink socket\n");
		return -1;
	}

	if (mnl_socket_bind(cpi->nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		ulogd_log(ULOGD_FATAL, "cannot bind netlink socket\n");
		return -1;
	}
	cpi->portid = mnl_socket_get_portid(cpi->nl);

	cpi->ufd.fd = mnl_socket_get_fd(cpi->nl);
	cpi->ufd.cb = &nfacct_read_cb;
	cpi->ufd.data = upi;
	cpi->ufd.when = ULOGD_FD_READ;

	ulogd_register_fd(&cpi->ufd);
	ulogd_init_timer(&cpi->timer, upi, polling_timer_cb);
	ulogd_add_timer(&cpi->timer,
			 pollint_ce(upi->config_kset).u.value);

	return 0;
}

static int destructor_nfacct(struct ulogd_pluginstance *upi)
{
	struct nfacct_pluginstance *cpi = (void *)upi->private;

	ulogd_del_timer(&cpi->timer);
	ulogd_unregister_fd(&cpi->ufd);
	mnl_socket_close(cpi->nl);

	return 0;
}

static void signal_nfacct(struct ulogd_pluginstance *upi, int signal)
{
	switch (signal) {
	case SIGUSR2:
		nfacct_send_request(upi);
		break;
	}
}

static struct ulogd_plugin nfacct_plugin = {
	.name = "NFACCT",
	.input = {
		.type = ULOGD_DTYPE_SOURCE,
	},
	.output = {
		.keys = nfacct_okeys,
		.num_keys = ARRAY_SIZE(nfacct_okeys),
		.type = ULOGD_DTYPE_SUM,
	},
	.config_kset	= &nfacct_kset,
	.interp		= NULL,
	.configure	= &configure_nfacct,
	.start		= &constructor_nfacct,
	.stop		= &destructor_nfacct,
	.signal		= &signal_nfacct,
	.priv_size	= sizeof(struct nfacct_pluginstance),
	.version	= VERSION,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	ulogd_register_plugin(&nfacct_plugin);
}
