/* ulogd_inppkt_ULOG.c - stackable input plugin for ULOG packets -> ulogd2
 *
 * (C) 2004-2005 by Harald Welte <laforge@gnumonks.org>
 */

#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>


#include <ulogd/ulogd.h>
#include <libipulog/libipulog.h>

#ifndef ULOGD_NLGROUP_DEFAULT
#define ULOGD_NLGROUP_DEFAULT	32
#endif

/* Size of the socket receive memory.  Should be at least the same size as the
 * 'nlbufsiz' module loadtime parameter of ipt_ULOG.o
 * If you have _big_ in-kernel queues, you may have to increase this number.  (
 * --qthreshold 100 * 1500 bytes/packet = 150kB  */
#define ULOGD_RMEM_DEFAULT	131071

/* Size of the receive buffer for the netlink socket.  Should be at least of
 * RMEM_DEFAULT size.  */
#define ULOGD_BUFSIZE_DEFAULT	150000

struct ulog_input {
	struct ipulog_handle *libulog_h;
	unsigned char *libulog_buf;
	struct ulogd_fd ulog_fd;
};

/* configuration entries */

static struct config_keyset libulog_kset = {
	.num_ces = 4,
	.ces = {
	{
		.key 	 = "bufsize",
		.type 	 = CONFIG_TYPE_INT,
		.options = CONFIG_OPT_NONE,
		.u.value = ULOGD_BUFSIZE_DEFAULT,
	},
	{
		.key	 = "nlgroup",
		.type	 = CONFIG_TYPE_INT,
		.options = CONFIG_OPT_NONE,
		.u.value = ULOGD_NLGROUP_DEFAULT,
	},
	{
		.key	 = "rmem",
		.type	 = CONFIG_TYPE_INT,
		.options = CONFIG_OPT_NONE,
		.u.value = ULOGD_RMEM_DEFAULT,
	},
	{
		.key	 = "numeric_label",
		.type	 = CONFIG_TYPE_INT,
		.options = CONFIG_OPT_NONE,
		.u.value = 0,
	},

	}
};
enum ulog_keys {
	ULOG_KEY_RAW_MAC = 0,
	ULOG_KEY_RAW_PCKT,
	ULOG_KEY_RAW_PCKTLEN,
	ULOG_KEY_RAW_PCKTCOUNT,
	ULOG_KEY_OOB_PREFIX,
	ULOG_KEY_OOB_TIME_SEC,
	ULOG_KEY_OOB_TIME_USEC,
	ULOG_KEY_OOB_MARK,
	ULOG_KEY_OOB_IN,
	ULOG_KEY_OOB_OUT,
	ULOG_KEY_OOB_HOOK,
	ULOG_KEY_RAW_MAC_LEN,
	ULOG_KEY_OOB_FAMILY,
	ULOG_KEY_OOB_PROTOCOL,
	ULOG_KEY_RAW_LABEL,
};

static struct ulogd_key output_keys[] = {
	[ULOG_KEY_RAW_MAC] = {
		.type = ULOGD_RET_RAW,
		.flags = ULOGD_RETF_NONE,
		.name = "raw.mac",
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_sourceMacAddress,
		},
	},
	[ULOG_KEY_RAW_PCKT] = {
		.type = ULOGD_RET_RAW,
		.flags = ULOGD_RETF_NONE,
		.name = "raw.pkt",
		.ipfix = {
			.vendor = IPFIX_VENDOR_NETFILTER,
			.field_id = 1,
			},
	},
	[ULOG_KEY_RAW_PCKTLEN] = {
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "raw.pktlen",
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = 1
		},
	},
	[ULOG_KEY_RAW_PCKTCOUNT] = {
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "raw.pktcount",
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = 2
		},
	},
	[ULOG_KEY_OOB_PREFIX] = {
		.type = ULOGD_RET_STRING,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.prefix",
	},
	[ULOG_KEY_OOB_TIME_SEC] = {
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.time.sec",
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = 22
		},
	},
	[ULOG_KEY_OOB_TIME_USEC] = {
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.time.usec",
	},
	[ULOG_KEY_OOB_MARK] = {
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.mark",
	},
	[ULOG_KEY_OOB_IN] = {
		.type = ULOGD_RET_STRING,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.in",
	},
	[ULOG_KEY_OOB_OUT] = {
		.type = ULOGD_RET_STRING,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.out",
	},
	[ULOG_KEY_OOB_HOOK] = {
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.hook",
		.ipfix = {
			.vendor = IPFIX_VENDOR_NETFILTER,
			.field_id = IPFIX_NF_hook,
		},
	},
	[ULOG_KEY_RAW_MAC_LEN] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "raw.mac_len",
	},
	[ULOG_KEY_OOB_FAMILY] = {
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.family",
	},
	[ULOG_KEY_OOB_PROTOCOL] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.protocol",
	},
	[ULOG_KEY_RAW_LABEL] = {
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "raw.label",
	},

};

static int interp_packet(struct ulogd_pluginstance *ip, ulog_packet_msg_t *pkt)
{
	struct ulogd_key *ret = ip->output.keys;

	if (pkt->mac_len) {
		ret[ULOG_KEY_RAW_MAC].u.value.ptr = pkt->mac;
		ret[ULOG_KEY_RAW_MAC].flags |= ULOGD_RETF_VALID;
		ret[ULOG_KEY_RAW_MAC_LEN].u.value.ui16 = pkt->mac_len;
		ret[ULOG_KEY_RAW_MAC_LEN].flags |= ULOGD_RETF_VALID;
	}

	ret[ULOG_KEY_RAW_LABEL].u.value.ui8 = ip->config_kset->ces[3].u.value;
	ret[ULOG_KEY_RAW_LABEL].flags |= ULOGD_RETF_VALID;

	/* include pointer to raw ipv4 packet */
	ret[ULOG_KEY_RAW_PCKT].u.value.ptr = pkt->payload;
	ret[ULOG_KEY_RAW_PCKT].flags |= ULOGD_RETF_VALID;
	ret[ULOG_KEY_RAW_PCKTLEN].u.value.ui32 = pkt->data_len;
	ret[ULOG_KEY_RAW_PCKTLEN].flags |= ULOGD_RETF_VALID;
	ret[ULOG_KEY_RAW_PCKTCOUNT].u.value.ui32 = 1;
	ret[ULOG_KEY_RAW_PCKTCOUNT].flags |= ULOGD_RETF_VALID;

	ret[ULOG_KEY_OOB_PREFIX].u.value.ptr = pkt->prefix;
	ret[ULOG_KEY_OOB_PREFIX].flags |= ULOGD_RETF_VALID;

	/* god knows why timestamp_usec contains crap if timestamp_sec == 0
	 * if (pkt->timestamp_sec || pkt->timestamp_usec) { */
	if (pkt->timestamp_sec) {
		ret[ULOG_KEY_OOB_TIME_SEC].u.value.ui32 = pkt->timestamp_sec;
		ret[ULOG_KEY_OOB_TIME_SEC].flags |= ULOGD_RETF_VALID;
		ret[ULOG_KEY_OOB_TIME_USEC].u.value.ui32 = pkt->timestamp_usec;
		ret[ULOG_KEY_OOB_TIME_USEC].flags |= ULOGD_RETF_VALID;
	} else {
		ret[ULOG_KEY_OOB_TIME_SEC].flags &= ~ULOGD_RETF_VALID;
		ret[ULOG_KEY_OOB_TIME_USEC].flags &= ~ULOGD_RETF_VALID;
	}

	ret[ULOG_KEY_OOB_MARK].u.value.ui32 = pkt->mark;
	ret[ULOG_KEY_OOB_MARK].flags |= ULOGD_RETF_VALID;
	ret[ULOG_KEY_OOB_IN].u.value.ptr = pkt->indev_name;
	ret[ULOG_KEY_OOB_IN].flags |= ULOGD_RETF_VALID;
	ret[ULOG_KEY_OOB_OUT].u.value.ptr = pkt->outdev_name;
	ret[ULOG_KEY_OOB_OUT].flags |= ULOGD_RETF_VALID;

	ret[ULOG_KEY_OOB_HOOK].u.value.ui8 = pkt->hook;
	ret[ULOG_KEY_OOB_HOOK].flags |= ULOGD_RETF_VALID;

	/* ULOG is IPv4 only */
	ret[ULOG_KEY_OOB_FAMILY].u.value.ui8 = AF_INET;
	ret[ULOG_KEY_OOB_FAMILY].flags |= ULOGD_RETF_VALID;
	/* Undef in ULOG but necessary */
	ret[ULOG_KEY_OOB_PROTOCOL].u.value.ui16 = 0;
	ret[ULOG_KEY_OOB_PROTOCOL].flags |= ULOGD_RETF_VALID;

	ulogd_propagate_results(ip);
	return 0;
}

static int ulog_read_cb(int fd, unsigned int what, void *param)
{
	struct ulogd_pluginstance *upi = (struct ulogd_pluginstance *)param;
	struct ulogd_pluginstance *npi = NULL;
	struct ulog_input *u = (struct ulog_input *) &upi->private;
	ulog_packet_msg_t *upkt;
	int len;

	if (!(what & ULOGD_FD_READ))
		return 0;

	while ((len = ipulog_read(u->libulog_h, u->libulog_buf,
				 upi->config_kset->ces[0].u.value, 1))) {
		if (len <= 0) {
			if (errno == EAGAIN)
				break;
			/* this is not supposed to happen */
			ulogd_log(ULOGD_ERROR, "ipulog_read = %d! "
				  "ipulog_errno = %d (%s), "
				  "errno = %d (%s)\n",
				  len, ipulog_errno,
				  ipulog_strerror(ipulog_errno),
				  errno, strerror(errno));
			break;
		}
		while ((upkt = ipulog_get_packet(u->libulog_h,
						 u->libulog_buf, len))) {
			/* since we support the re-use of one instance in
			 * several different stacks, we duplicate the message
			 * to let them know */
			llist_for_each_entry(npi, &upi->plist, plist)
				interp_packet(npi, upkt);
			interp_packet(upi, upkt);
		}
	}
	return 0;
}

static int configure(struct ulogd_pluginstance *upi,
		     struct ulogd_pluginstance_stack *stack)
{
	return config_parse_file(upi->id, upi->config_kset);
}
static int init(struct ulogd_pluginstance *upi)
{
	struct ulog_input *ui = (struct ulog_input *) &upi->private;

	ui->libulog_buf = malloc(upi->config_kset->ces[0].u.value);
	if (!ui->libulog_buf) {
		ulogd_log(ULOGD_ERROR, "Out of memory\n");
		goto out_buf;
	}

	ui->libulog_h = ipulog_create_handle(
				ipulog_group2gmask(upi->config_kset->ces[1].u.value),
				upi->config_kset->ces[2].u.value);
	if (!ui->libulog_h) {
		ulogd_log(ULOGD_ERROR, "Can't create ULOG handle\n");
		goto out_handle;
	}

	ui->ulog_fd.fd = ipulog_get_fd(ui->libulog_h);
	ui->ulog_fd.cb = &ulog_read_cb;
	ui->ulog_fd.data = upi;
	ui->ulog_fd.when = ULOGD_FD_READ;

	ulogd_register_fd(&ui->ulog_fd);

	return 0;

out_handle:
	free(ui->libulog_buf);
out_buf:
	return -1;
}

static int fini(struct ulogd_pluginstance *pi)
{
	struct ulog_input *ui = (struct ulog_input *)pi->private;

	ulogd_unregister_fd(&ui->ulog_fd);
	free(pi);

	return 0;
}

struct ulogd_plugin libulog_plugin = {
	.name = "ULOG",
	.input = {
		.type = ULOGD_DTYPE_SOURCE,
		.keys = NULL,
		.num_keys = 0,
	},
	.output = {
		.type = ULOGD_DTYPE_RAW,
		.keys = output_keys,
		.num_keys = sizeof(output_keys)/sizeof(struct ulogd_key),
	},
	.configure = &configure,
	.start = &init,
	.stop = &fini,
	.config_kset = &libulog_kset,
	.version = ULOGD_VERSION,
};

void __attribute__ ((constructor)) initializer(void)
{
	ulogd_register_plugin(&libulog_plugin);
}
