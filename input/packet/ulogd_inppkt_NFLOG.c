/* ulogd_inppkt_ULOG.c - stackable input plugin for ULOG packets -> ulogd2
 * (C) 2004-2005 by Harald Welte <laforge@gnumonks.org>
 */

#include <unistd.h>
#include <stdlib.h>

#include <ulogd/ulogd.h>
#include <libnfnetlink_log/libnfnetlink_log.h>

#ifndef NFLOG_GROUP_DEFAULT
#define NFLOG_GROUP_DEFAULT	0
#endif

/* Size of the socket recevive memory.  Should be at least the same size as the
 * 'nlbufsiz' module loadtime parameter of ipt_ULOG.o
 * If you have _big_ in-kernel queues, you may have to increase this number.  (
 * --qthreshold 100 * 1500 bytes/packet = 150kB  */
#define NFLOG_RMEM_DEFAULT	131071

/* Size of the receive buffer for the netlink socket.  Should be at least of
 * RMEM_DEFAULT size.  */
#define NFLOG_BUFSIZE_DEFAULT	150000

struct nful_input {
	struct nfulnl_handle nful_h;
	struct nfulnl_g_handle nful_gh;
	unsigned char *nfulog_buf;
	struct ulogd_fd nful_fd;
};

/* configuration entries */

static struct config_keyset libulog_kset = {
	.num_ces = 10,
	.ces = {
	{
		.key 	 = "bufsize",
		.type 	 = CONFIG_TYPE_INT,
		.options = CONFIG_OPT_NONE,
		.u.value = NFLOG_BUFSIZE_DEFAULT,
	},
	{
		.key	 = "group",
		.type	 = CONFIG_TYPE_INT,
		.options = CONFIG_OPT_NONE,
		.u.value = NFLOG_GROUP_DEFAULT,
	},
	{
		.key	 = "rmem",
		.type	 = CONFIG_TYPE_INT,
		.options = CONFIG_OPT_NONE,
		.u.value = NFLOG_RMEM_DEFAULT,
	},
	}
};

#define bufsiz_ce(x)	(x[0])
#define group_ce(x)	(x[1])
#define rmem_ce(x)	(x[2])


static struct ulogd_key output_keys[] = {
	{ 
		.type = ULOGD_RET_STRING, 
		.flags = ULOGD_RETF_FREE, 
		.name = "raw.mac", 
	},
	{
		.type = ULOGD_RET_RAW,
		.flags = ULOGD_RETF_FREE,
		.name = "raw.pkt",
		.ipfix = {
			.vendor = IPFIX_VENDOR_NETFILTER,
			.field_id = 1,
			},
	},
	{
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "raw.pktlen",
		.ipfix = { 
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = 1
		},
	},
	{
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "raw.pktcount",
		.ipfix = { 
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = 2
		},
	},
	{
		.type = ULOGD_RET_STRING,
		.flags = ULOGD_RETF_NONE, 
		.name = "oob.prefix", 
	},
	{ 	.type = ULOGD_RET_UINT32, 
		.flags = ULOGD_RETF_NONE, 
		.name = "oob.time.sec", 
		.ipfix = { 
			.vendor = IPFIX_VENDOR_IETF, 
			.field_id = 22 
		},
	},
	{
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.time.usec", 
	},
	{
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.mark", 
	},
	{
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.ifindex_in", 
	},
	{
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.ifindex_out", 
	},
};

static int interp_packet(struct ulogd_pluginstance *ip, ulog_packet_msg_t *pkt)
{
	unsigned char *p;
	int i;
	char *buf, *oldbuf = NULL;
	struct ulogd_key *ret = ip->output;

	if (pkt->mac_len) {
		buf = (char *) malloc(3 * pkt->mac_len + 1);
		if (!buf) {
			ulogd_log(ULOGD_ERROR, "OOM!!!\n");
			return -1;
		}
		*buf = '\0';

		p = pkt->mac;
		oldbuf = buf;
		for (i = 0; i < pkt->mac_len; i++, p++)
			sprintf(buf, "%s%02x%c", oldbuf, *p, i==pkt->mac_len-1 ? ' ':':');
		ret[0].u.value.ptr = buf;
		ret[0].flags |= ULOGD_RETF_VALID;
	}

	/* include pointer to raw ipv4 packet */
	ret[1].u.value.ptr = pkt->payload;
	ret[1].flags |= ULOGD_RETF_VALID;
	ret[2].u.value.ui32 = pkt->data_len;
	ret[2].flags |= ULOGD_RETF_VALID;
	ret[3].u.value.ui32 = 1;
	ret[3].flags |= ULOGD_RETF_VALID;

	ret[4].u.value.ptr = pkt->prefix;
	ret[4].flags |= ULOGD_RETF_VALID;

	/* god knows why timestamp_usec contains crap if timestamp_sec == 0
	 * if (pkt->timestamp_sec || pkt->timestamp_usec) { */
	if (pkt->timestamp_sec) {
		ret[5].u.value.ui32 = pkt->timestamp_sec;
		ret[5].flags |= ULOGD_RETF_VALID;
		ret[6].u.value.ui32 = pkt->timestamp_usec;
		ret[6].flags |= ULOGD_RETF_VALID;
	} else {
		ret[5].flags &= ~ULOGD_RETF_VALID;
		ret[6].flags &= ~ULOGD_RETF_VALID;
	}

	ret[7].u.value.ui32 = pkt->mark;
	ret[7].flags |= ULOGD_RETF_VALID;
	ret[8].u.value.ptr = pkt->indev_name;
	ret[8].flags |= ULOGD_RETF_VALID;
	ret[9].u.value.ptr = pkt->outdev_name;
	ret[9].flags |= ULOGD_RETF_VALID;
	
	return 0;
}

static int nful_read_cb(int fd, unsigned int what, void *param)
{
	struct ulogd_pluginstance *upi = (struct ulogd_pluginstance *)param;
	struct nful_input *u = (struct nful_input *)upi->private;
	int len;

	if (!(what & ULOGD_FD_READ))
		return 0;
#if 0
	while (len = ipulog_read(u->libulog_h, u->libulog_buf,
				 bufsiz_ce(upi->configs).u.value, 1)) {
		if (len <= 0) {
			/* this is not supposed to happen */
			ulogd_log(ULOGD_ERROR, "ipulog_read = %d! "
				  "ipulog_errno = %d, errno = %d\n",
				  len, ipulog_errno, errno);
			break;
		}
		while ((upkt = ipulog_get_packet(u->libulog_h,
						 u->libulog_buf, len))) {
			ulogd_log(ULOGD_DEBUG, "==> ulog packet received\n");
			interp_packet(upi, upkt);
		}
	}
#endif
	return 0;
}

static struct ulogd_pluginstance *init(struct ulogd_plugin *pl)
{
	struct nful_input *ui;
	struct ulogd_pluginstance *upi = malloc(sizeof(*upi)+sizeof(*ui));

	if (!upi)
		return NULL;

	ui = (struct nful_input *) upi->private;
	upi->plugin = pl;
	upi->input = NULL;
	/* FIXME: upi->output = */

	ui->nfulog_buf = malloc(bufsiz_ce(upi->configs).u.value);
	if (!ui->nfulog_buf)
		goto out_buf;

	if (nfulnl_open(&ui->nful_h) < 0)
		goto out_handle;

	/* FIXME: config entry for af's */
	/* FIXME: forced unbind of existing handler */
	if (nfulnl_bind_pf(&ui->nful_h, AF_INET) < 0)
		goto out_bind_pf;

	if (nfulnl_bind_group(&ui->nful_h, &ui->nful_gh,
			      group_ce(upi->configs).u.value) < 0)
		goto out_bind;

	//nfulnl_set_nlbufsiz(&ui->nful_gh, );
	//nfnl_set_rcvbuf();

	ui->ulog_fd.fd = nfulnl_get_fd(&ui->nfulnl_h);
	ui->ulog_fd.cb = &nfulnl_read_cb;
	ui->ulog_fd.data = upi;

	ulogd_register_fd(&ui->nful_fd);

	return upi;

out_bind:
	nfulnl_close(&ui->nful_h);
out_handle:
	free(ui->libulog_buf);
out_buf:
	free(upi);
	return NULL;
}

static int fini(struct ulogd_pluginstance *pi)
{
	struct nful_input *ui = (struct nful_input *)pi->private;

	ulogd_unregister_fd(&ui->nful_fd);
	nfulnl_unbind_group(&ui->nful_gh);
	nfulnl_close(&ui->nful_h);

	free(pi);

	return 0;
}

struct ulogd_plugin libulog_plugin = {
	.name = "NFLOG",
	.input = {
			.type = ULOGD_DTYPE_SOURCE,
		},
	.output = {
			.type = ULOGD_DTYPE_RAW,
			.keys = &output_keys,
			.num_keys = sizeof(output_keys)/sizeof(struct ulogd_key),
		},
	.constructor = &init,
	.destructor = &fini,
	.config_kset = &libulog_kset,
};

void _init(void)
{
	ulogd_register_plugin(&libulog_plugin);
}
