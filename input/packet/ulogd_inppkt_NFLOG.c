/* ulogd_inppkt_NFLOG.c - stackable input plugin for NFLOG packets -> ulogd2
 *
 * (C) 2004-2005 by Harald Welte <laforge@gnumonks.org>
 */

#include <unistd.h>
#include <stdlib.h>
#include <netinet/in.h>

#include <ulogd/ulogd.h>
#include <libnetfilter_log/libnetfilter_log.h>

#ifndef NFLOG_GROUP_DEFAULT
#define NFLOG_GROUP_DEFAULT	0
#endif

/* Size of the socket receive memory.  Should be at least the same size as the
 * 'nlbufsiz' parameter of nfnetlink_log.ko
 * If you have _big_ in-kernel queues, you may have to increase this number.  (
 * --qthreshold 100 * 1500 bytes/packet = 150kB  */
#define NFLOG_RMEM_DEFAULT	131071

/* Size of the receive buffer for the netlink socket.  Should be at least of
 * RMEM_DEFAULT size.  */
#define NFLOG_BUFSIZE_DEFAULT	150000

struct nflog_input {
	struct nflog_handle *nful_h;
	struct nflog_g_handle *nful_gh;
	unsigned char *nfulog_buf;
	struct ulogd_fd nful_fd;
};

/* configuration entries */

static struct config_keyset libulog_kset = {
	.num_ces = 7,
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
		{
			.key	 = "unbind",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 1,
		},
		{
			.key	 = "seq_local",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 0,
		},
		{
			.key	 = "seq_global",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 0,
		},
	}
};

#define bufsiz_ce(x)	(x->ces[0])
#define group_ce(x)	(x->ces[1])
#define rmem_ce(x)	(x->ces[2])
#define af_ce(x)	(x->ces[3])
#define unbind_ce(x)	(x->ces[4])
#define seq_ce(x)	(x->ces[4])
#define seq_global_ce(x)	(x->ces[5])

enum nflog_keys {
	NFLOG_KEY_RAW_MAC = 0,
	NFLOG_KEY_RAW_PCKT,
	NFLOG_KEY_RAW_PCKTLEN,
	NFLOG_KEY_RAW_PCKTCOUNT,
	NFLOG_KEY_OOB_PREFIX,
	NFLOG_KEY_OOB_TIME_SEC,
	NFLOG_KEY_OOB_TIME_USEC,
	NFLOG_KEY_OOB_MARK,
	NFLOG_KEY_OOB_IFINDEX_IN,
	NFLOG_KEY_OOB_IFINDEX_OUT,
	NFLOG_KEY_OOB_HOOK,
	NFLOG_KEY_RAW_MAC_LEN,
	NFLOG_KEY_OOB_SEQ_LOCAL,
	NFLOG_KEY_OOB_SEQ_GLOBAL,
	NFLOG_KEY_OOB_PROTOCOL,
	NFLOG_KEY_OOB_UID,
};

static struct ulogd_key output_keys[] = {
	{ 
		.type = ULOGD_RET_RAW, 
		.flags = ULOGD_RETF_NONE,
		.name = "raw.mac", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_sourceMacAddress,
		},
	},
	{
		.type = ULOGD_RET_RAW,
		.flags = ULOGD_RETF_NONE,
		.name = "raw.pkt",
		.ipfix = {
			.vendor = IPFIX_VENDOR_NETFILTER,
			.field_id = IPFIX_NF_rawpacket,
		},
	},
	{
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "raw.pktlen",
		.ipfix = { 
			.vendor = IPFIX_VENDOR_NETFILTER,
			.field_id = IPFIX_NF_rawpacket_length,
		},
	},
	{
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "raw.pktcount",
		.ipfix = { 
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_packetDeltaCount,
		},
	},
	{
		.type = ULOGD_RET_STRING,
		.flags = ULOGD_RETF_NONE, 
		.name = "oob.prefix", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_NETFILTER,
			.field_id = IPFIX_NF_prefix,  
		},
	},
	{ 	.type = ULOGD_RET_UINT32, 
		.flags = ULOGD_RETF_NONE, 
		.name = "oob.time.sec", 
		.ipfix = { 
			.vendor = IPFIX_VENDOR_IETF, 
			.field_id = IPFIX_flowStartSeconds, 
		},
	},
	{
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.time.usec", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_flowStartMicroSeconds,
		},
	},
	{
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.mark", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_NETFILTER,
			.field_id = IPFIX_NF_mark,
		},
	},
	{
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.ifindex_in", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_ingressInterface,
		},
	},
	{
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.ifindex_out", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_egressInterface,
		},
	},
	{
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.hook",
		.ipfix = {
			.vendor = IPFIX_VENDOR_NETFILTER,
			.field_id = IPFIX_NF_hook,
		},
	},
	{ 
		.type = ULOGD_RET_STRING, 
		.flags = ULOGD_RETF_NONE, 
		.name = "raw.mac_len", 
	},
	{
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.seq.local",
		.ipfix = {
			.vendor = IPFIX_VENDOR_NETFILTER,
			.field_id = IPFIX_NF_seq_local,
		},
	},
	{
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.seq.global",
		.ipfix = {
			.vendor = IPFIX_VENDOR_NETFILTER,
			.field_id = IPFIX_NF_seq_global,
		},
	},
	{
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.protocol",
	},
	{
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.uid",
	},

};

static inline int 
interp_packet(struct ulogd_pluginstance *upi, struct nflog_data *ldata)
{
	struct ulogd_key *ret = upi->output.keys;

	struct nfulnl_msg_packet_hdr *ph = nflog_get_msg_packet_hdr(ldata);
	struct nfulnl_msg_packet_hw *hw = nflog_get_packet_hw(ldata);
	char *payload;
	int payload_len = nflog_get_payload(ldata, &payload);
	char *prefix = nflog_get_prefix(ldata);
	struct timeval ts;
	u_int32_t mark = nflog_get_nfmark(ldata);
	u_int32_t indev = nflog_get_indev(ldata);
	u_int32_t outdev = nflog_get_outdev(ldata);
	u_int32_t seq;
	u_int32_t uid;
	

	if (ph) {
		/* FIXME */
		ret[NFLOG_KEY_OOB_HOOK].u.value.ui8 = ph->hook;
		ret[NFLOG_KEY_OOB_HOOK].flags |= ULOGD_RETF_VALID;
		ret[NFLOG_KEY_OOB_PROTOCOL].u.value.ui16 = ntohs(ph->hw_protocol);
		ret[NFLOG_KEY_OOB_PROTOCOL].flags |= ULOGD_RETF_VALID;
	}

	if (hw) {
		ret[NFLOG_KEY_RAW_MAC].u.value.ptr = hw->hw_addr;
		ret[NFLOG_KEY_RAW_MAC].flags |= ULOGD_RETF_VALID;
		ret[NFLOG_KEY_RAW_MAC_LEN].u.value.ui16 = ntohs(hw->hw_addrlen);
		ret[NFLOG_KEY_RAW_MAC_LEN].flags |= ULOGD_RETF_VALID;
	}

	if (payload_len >= 0) {
		/* include pointer to raw packet */
		ret[NFLOG_KEY_RAW_PCKT].u.value.ptr = payload;
		ret[NFLOG_KEY_RAW_PCKT].flags |= ULOGD_RETF_VALID;

		ret[NFLOG_KEY_RAW_PCKTLEN].u.value.ui32 = payload_len;
		ret[NFLOG_KEY_RAW_PCKTLEN].flags |= ULOGD_RETF_VALID;
	}

	/* number of packets */
	ret[NFLOG_KEY_RAW_PCKTCOUNT].u.value.ui32 = 1;
	ret[NFLOG_KEY_RAW_PCKTCOUNT].flags |= ULOGD_RETF_VALID;

	if (prefix) {
		ret[NFLOG_KEY_OOB_PREFIX].u.value.ptr = prefix;
		ret[NFLOG_KEY_OOB_PREFIX].flags |= ULOGD_RETF_VALID;
	}

	/* god knows why timestamp_usec contains crap if timestamp_sec
	 * == 0 if (pkt->timestamp_sec || pkt->timestamp_usec) { */
	if (nflog_get_timestamp(ldata, &ts) == 0 && ts.tv_sec) {
		/* FIXME: convert endianness */
		ret[NFLOG_KEY_OOB_TIME_SEC].u.value.ui32 = ts.tv_sec & 0xffffffff;
		ret[NFLOG_KEY_OOB_TIME_SEC].flags |= ULOGD_RETF_VALID;
		ret[NFLOG_KEY_OOB_TIME_USEC].u.value.ui32 = ts.tv_usec & 0xffffffff;
		ret[NFLOG_KEY_OOB_TIME_USEC].flags |= ULOGD_RETF_VALID;
	}

	ret[NFLOG_KEY_OOB_MARK].u.value.ui32 = mark;
	ret[NFLOG_KEY_OOB_MARK].flags |= ULOGD_RETF_VALID;

	if (indev > 0) {
		ret[NFLOG_KEY_OOB_IFINDEX_IN].u.value.ui32 = indev;
		ret[NFLOG_KEY_OOB_IFINDEX_IN].flags |= ULOGD_RETF_VALID;
	}

	if (outdev > 0) {
		ret[NFLOG_KEY_OOB_IFINDEX_OUT].u.value.ui32 = outdev;
		ret[NFLOG_KEY_OOB_IFINDEX_OUT].flags |= ULOGD_RETF_VALID;
	}

	if (nflog_get_uid(ldata, &uid) == 0) {
		ret[NFLOG_KEY_OOB_UID].u.value.ui32 = uid;
		ret[NFLOG_KEY_OOB_UID].flags |= ULOGD_RETF_VALID;
	}

	if (nflog_get_seq(ldata, &seq) == 0) {
		ret[NFLOG_KEY_OOB_SEQ_LOCAL].u.value.ui32 = seq;
		ret[NFLOG_KEY_OOB_SEQ_LOCAL].flags |= ULOGD_RETF_VALID;
	}
	if (nflog_get_seq_global(ldata, &seq) == 0) {
		ret[NFLOG_KEY_OOB_SEQ_GLOBAL].u.value.ui32 = seq;
		ret[NFLOG_KEY_OOB_SEQ_GLOBAL].flags |= ULOGD_RETF_VALID;
	}
	ulogd_propagate_results(upi);
	return 0;
}

/* callback called from ulogd core when fd is readable */
static int nful_read_cb(int fd, unsigned int what, void *param)
{
	struct ulogd_pluginstance *upi = (struct ulogd_pluginstance *)param;
	struct nflog_input *ui = (struct nflog_input *)upi->private;
	int len;

	if (!(what & ULOGD_FD_READ))
		return 0;

	/* we don't have a while loop here, since we don't want to
	 * grab all the processing time just for us.  there might be other
	 * sockets that have pending work */
	len = recv(fd, ui->nfulog_buf, bufsiz_ce(upi->config_kset).u.value, 0);
	if (len < 0)
		return len;

	nflog_handle_packet(ui->nful_h, (char *)ui->nfulog_buf, len);

	return 0;
}

/* callback called by libnfnetlink* for every nlmsg */
static int msg_cb(struct nflog_g_handle *gh, struct nfgenmsg *nfmsg,
		  struct nflog_data *nfa, void *data)
{
	struct ulogd_pluginstance *upi = data;

	return interp_packet(upi, nfa);
}

static int configure(struct ulogd_pluginstance *upi,
		     struct ulogd_pluginstance_stack *stack)
{
	ulogd_log(ULOGD_DEBUG, "parsing config file section `%s', "
		  "plugin `%s'\n", upi->id, upi->plugin->name);

	config_parse_file(upi->id, upi->config_kset);
	return 0;
}

static int start(struct ulogd_pluginstance *upi)
{
	struct nflog_input *ui = (struct nflog_input *) upi->private;
	unsigned int flags;

	ui->nfulog_buf = malloc(bufsiz_ce(upi->config_kset).u.value);
	if (!ui->nfulog_buf)
		goto out_buf;

	ulogd_log(ULOGD_DEBUG, "opening nfnetlink socket\n");
	ui->nful_h = nflog_open();
	if (!ui->nful_h)
		goto out_handle;

	if (unbind_ce(upi->config_kset).u.value > 0) {
		ulogd_log(ULOGD_NOTICE, "forcing unbind of existing log "
			  "handler for protocol %d\n", 
			  af_ce(upi->config_kset).u.value);
		if (nflog_unbind_pf(ui->nful_h, 
				    af_ce(upi->config_kset).u.value) < 0) {
			ulogd_log(ULOGD_ERROR, "unable to force-unbind "
				  "existing log handler for protocol %d\n",
			  	  af_ce(upi->config_kset).u.value);
			goto out_handle;
		}
	}

	ulogd_log(ULOGD_DEBUG, "binding to protocol family %d\n",
		  af_ce(upi->config_kset).u.value);
	if (nflog_bind_pf(ui->nful_h, af_ce(upi->config_kset).u.value) < 0) {
		ulogd_log(ULOGD_ERROR, "unable to bind to protocol family %d\n",
			  af_ce(upi->config_kset).u.value);
		goto out_bind_pf;
	}

	ulogd_log(ULOGD_DEBUG, "binding to log group %d\n",
		  group_ce(upi->config_kset).u.value);
	ui->nful_gh = nflog_bind_group(ui->nful_h,
				       group_ce(upi->config_kset).u.value);
	if (!ui->nful_gh) {
		ulogd_log(ULOGD_ERROR, "unable to bind to log group %d\n",
			  group_ce(upi->config_kset).u.value);
		goto out_bind;
	}

	nflog_set_mode(ui->nful_gh, NFULNL_COPY_PACKET, 0xffff);

	//nflog_set_nlbufsiz(&ui->nful_gh, );
	//nfnl_set_rcvbuf();
	
	/* set log flags based on configuration */
	flags = 0;
	if (seq_ce(upi->config_kset).u.value != 0)
		flags = NFULNL_CFG_F_SEQ;
	if (seq_ce(upi->config_kset).u.value != 0)
		flags |= NFULNL_CFG_F_SEQ_GLOBAL;
	if (flags) {
		if (nflog_set_flags(ui->nful_gh, flags) < 0)
			ulogd_log(ULOGD_ERROR, "unable to set flags 0x%x\n",
				  flags);
	}
	
	nflog_callback_register(ui->nful_gh, &msg_cb, upi);

	ui->nful_fd.fd = nflog_fd(ui->nful_h);
	ui->nful_fd.cb = &nful_read_cb;
	ui->nful_fd.data = upi;
	ui->nful_fd.when = ULOGD_FD_READ;

	if (ulogd_register_fd(&ui->nful_fd) < 0)
		goto out_bind;

	return 0;

out_bind:
	nflog_close(ui->nful_h);
out_bind_pf:
	nflog_unbind_pf(ui->nful_h, af_ce(upi->config_kset).u.value);
out_handle:
	free(ui->nfulog_buf);
out_buf:
	return -1;
}

static int stop(struct ulogd_pluginstance *pi)
{
	struct nflog_input *ui = (struct nflog_input *)pi->private;

	ulogd_unregister_fd(&ui->nful_fd);
	nflog_unbind_group(ui->nful_gh);
	nflog_close(ui->nful_h);

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
			.keys = output_keys,
			.num_keys = sizeof(output_keys)/sizeof(struct ulogd_key),
		},
	.priv_size 	= sizeof(struct nflog_input),
	.configure 	= &configure,
	.start 		= &start,
	.stop 		= &stop,
	.config_kset 	= &libulog_kset,
	.version	= ULOGD_VERSION,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	ulogd_register_plugin(&libulog_plugin);
}
