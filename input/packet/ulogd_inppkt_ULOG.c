/* ulogd_inppkt_ULOG.c - stackable input plugin for ULOG packets -> ulogd2
 * (C) 2004 by Harald Welte <laforge@gnumonks.org>
 */

#include <ulogd/ulogd.h>
#include <ulogd/conffile.h>

#include <libipulog/libipulog.h>

/* Size of the socket recevive memory.  Should be at least the same size as the
 * 'nlbufsiz' module loadtime parameter of ipt_ULOG.o
 * If you have _big_ in-kernel queues, you may have to increase this number.  (
 * --qthreshold 100 * 1500 bytes/packet = 150kB  */
#define ULOGD_RMEM_DEFAULT	131071

/* Size of the receive buffer for the netlink socket.  Should be at least of
 * RMEM_DEFAULT size.  */
#define ULOGD_BUFSIZE_DEFAULT	150000

struct ulog_input {
	struct ipulog_handle *libulog_h;
	static unsigned char *libulog_buf;
	static struct ulogd_fd ulog_fd;
};

/* configuration entries */
static config_entry_t bufsiz_ce = { NULL, "bufsize", CONFIG_TYPE_INT,       
				   CONFIG_OPT_NONE, 0,
				   { value: ULOGD_BUFSIZE_DEFAULT } }; 

static config_entry_t nlgroup_ce = { &bufsiz_ce, "nlgroup", CONFIG_TYPE_INT,
				     CONFIG_OPT_NONE, 0,
				     { value: ULOGD_NLGROUP_DEFAULT } };

static config_entry_t rmem_ce = { &nlgroup_ce, "rmem", CONFIG_TYPE_INT,
				  CONFIG_OPT_NONE, 0, 
				  { value: ULOGD_RMEM_DEFAULT } };


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
		.type = ULOGD_RET_STRING,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.in", 
	},
	{
		.type = ULOGD_RET_STRING,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.out", 
	},
};

static int interp_packet(struct ulogd_pluginstance *ip, ulog_packet_msg_t *pkt)
{
	unsigned char *p;
	int i;
	char *buf, *oldbuf = NULL;
	ulog_iret_t *ret = ip->result;

	if (pkt->mac_len) {
		buf = (char *) malloc(3 * pkt->mac_len + 1);
		if (!buf) {
			ulogd_log(ULOGD_ERROR, "OOM!!!\n");
			return NULL;
		}
		*buf = '\0';

		p = pkt->mac;
		oldbuf = buf;
		for (i = 0; i < pkt->mac_len; i++, p++)
			sprintf(buf, "%s%02x%c", oldbuf, *p, i==pkt->mac_len-1 ? ' ':':');
		ret[0].value.ptr = buf;
		ret[0].flags |= ULOGD_RETF_VALID;
	}

	/* include pointer to raw ipv4 packet */
	ret[1].value.ptr = pkt->payload;
	ret[1].flags |= ULOGD_RETF_VALID;
	ret[2].value.ui32 = pkt->data_len;
	ret[2].flags |= ULOGD_RETF_VALID;
	ret[3].value.ui32 = 1;
	ret[3].flags |= ULOGD_RETF_VALID;

	ret[4].value.ptr = pkt->prefix;
	ret[4].flags |= ULOGD_RETF_VALID;

	/* god knows why timestamp_usec contains crap if timestamp_sec == 0
	 * if (pkt->timestamp_sec || pkt->timestamp_usec) { */
	if (pkt->timestamp_sec) {
		ret[5].value.ui32 = pkt->timestamp_sec;
		ret[5].flags |= ULOGD_RETF_VALID;
		ret[6].value.ui32 = pkt->timestamp_usec;
		ret[6].flags |= ULOGD_RETF_VALID;
	} else {
		ret[5].flags &= ~ULOGD_RETF_VALID;
		ret[6].flags &= ~ULOGD_RETF_VALID;
	}

	ret[7].value.ui32 = pkt->mark;
	ret[7].flags |= ULOGD_RETF_VALID;
	ret[8].value.ptr = pkt->indev_name;
	ret[8].flags |= ULOGD_RETF_VALID;
	ret[9].value.ptr = pkt->outdev_name;
	ret[9].flags |= ULOGD_RETF_VALID;
	
	return ret;
}

static struct ulog_read_cb(int fd, void *param)
{
	struct ulogd_pluginstance *upi = (struct ulogd_pluginstance *)param;
	struct ulog_input *u = (struct ulog_input *)param->private;
	ulog_packet_msg_t *upkt;
	int len;

	while (len = ipulog_read(u->libulog_h, u->libulog_buf,
				 bufsiz_ce.u.value, 1)) {
		if (len <= 0) {
			/* this is not supposed to happen */
			ulogd_log(ULOGD_ERROR, "ipulog_read = %d! "
				  "ipulog_errno = %d, errno = %d\n",
				  len, ipulog_errno, errno);
			break;
		}
		while ((upkt = ipulog_get_packet(u->libulog_h,
						 u->libulog_buf, len))) {
			DEBUGP("==> ulog packet received\n");
			interp_packet(upi, upkt);
		}
	}
	return 0;
}

static struct ulogd_pluginstance *init(struct ulogd_plugin *pl)
{
	struct ulog_input *ui;
	struct ulogd_pluginstance *upi = malloc(sizeof(*upi)+sizeof(*ui));

	if (!upi)
		return NULL;

	ui = (struct ulog_input *) upi->private;
	upi->plugin = pl;
	upi->input = NULL;
	/* FIXME: upi->output = */

	ui->libulog_buf = malloc(bufsiz_ce.u.value);
	if (!ui->libulog_buf)
		goto out_buf;

	ui->libulog_h = ipulog_create_handle(
				ipulog_group2gmask(nlgroup_ce.u.value),
				rmem_ce.u.value);
	if (!libulog_h)
		goto out_handle;

	ui->ulog_fd.fd = ui->libulog_h->fd;
	ui->ulog_fd.cb = &ulog_read_cb;
	ui->ulog_fd.data = upi;

	ulogd_register_fd(&ui->ulog_fd);

	return ui;
out_handle:
	free(ui->libulog_buf);
out_buf:
	free(upi);
	return NULL;
}

static int fini(struct ulogd_pluginstance *pi)
{
}

struct ulogd_plugin libulog_plugin = {
	.name = "ULOG",
	.input = {
			.type = ULOGD_DTYPE_NULL,
		},
	.output = {
			.type = ULOGD_DTYPE_RAW,
			.keys = &ulog_output_key,
			.num = 10,
		},
	.constructor = &init,
	.destructor = &fini,
	.configs = &rmem_ce,
};

void _init(void)
{
	ulogd_register_plugin(&libulog_plugin);
}
