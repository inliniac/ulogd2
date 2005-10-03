/* ulogd_input_CTNL.c, Version $Revision$
 *
 * ulogd input plugin for ctnetlink
 *
 * (C) 2005 by Harald Welte <laforge@gnumonks.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation
 */

#include <errno.h>
#include <ulogd/ulogd.h>
#include <libnfnetlink/libnfnetlink.h>
#include <libnfnetlink_conntrack/libnfnetlink_conntrack.h>

struct ctnl_pluginstance {
	struct ctnl_handle *cth;
	struct ulogd_fd ctnl_fd;
};

#if 0
static int ctnl_parser(struct ulogd_pluginstance *pi,
		       struct nfattr *_attr, struct nlmsghdr *nlh)
{
	struct nfattr *attr = NFM_NFA(NLMSG_DATA(nlh));
	struct ip_conntrack_tuple *orig;
	struct cta_countrs *ctr;

	/* FIXME: what about reply direction ? */
	while (NFA_OK(attr, attrlen)) {
		switch (attr->nfa_type) {
		case CTA_ORIG:
			orig = NFA_DATA(attr);
			pi->output.keys[0].u.ui32 = orig->src.ip;
			pi->output.keys[1].u.ui32 = orig->dst.ip;
			pi->output.keys[2].u.value.ui8 = orig->dst.protonum;
			/* FIXME: l4 port numbers */
			break;
		case CTA_COUNTERS:
			ctr = NFA_DATA(attr);
			pi->output.keys[5].u.value.ui32 = ctr->orig.bytes;
			pi->output.keys[6].u.value.ui32 = ctr->prog.packets;
			break;
		}
		attr = NFA_NEXT(attr, attrlen);
	}
	return 0;
}
#endif

static int event_handler(struct sockaddr_nl *sock, struct nlmsghdr *nlh,
			 void *arg)
{
	struct nfgenmsg *nfmsg;
	struct nfattr *nfa;
	int min_len = 0;
	int type = NFNL_MSG_TYPE(nlh->nlmsg_type);

	nfmsg = NLMSG_DATA(nlh);

	min_len = sizeof(struct nfgenmsg);
	if (nlh->nlmsg_len < min_len)
		return -EINVAL;

#if 0 
	if (type == IPCTNL_MSG_CT_NEW && flags & NLM_F_CREATE) {
		/* FIXME: build hash table with timestamp of start of
		 * connection */
	} else if (type == IPCTNL_MSG_CT_DELETE) {
		/* We have the final count of bytes for this connection */
	}
#endif
	return 0;
}

static struct ctnl_msg_handler new_h = {
	.type = IPCTNL_MSG_CT_NEW,
	.handler = event_handler,
};

static struct ctnl_msg_handler destroy_h = {
	.type = IPCTNL_MSG_CT_DELETE,
	.handler = event_handler,
};

static int read_cb_ctnl(int fd, unsigned int what, void *param)
{
	struct ctnl_pluginstance *cpi = 
				(struct ulogd_ctnl_pluginstance *) param;

	if (!(what & ULOGD_FD_READ))
		return 0;

	/* FIXME: implement this */
	ctnl_event_conntrack(&cpi->cth, AF_INET);
}

static int constructor_ctnl(struct ulogd_pluginstance *upi)
{
	struct ctnl_pluginstance *cpi = 
			(struct ctnl_pluginstance *)upi->private;

	memset(cpi, NULL, sizeof(*cpi));

	/* FIXME: make eventmask configurable */
	cpi->cth = ctnl_open(NFNL_SUBSYS_CTNETLINK, NF_NETLINK_CONNTRACK_NEW|
			     NF_NETLINK_CONNTRACK_DESTROY);
	if (!cph->cth) {
		print("error opening ctnetlink\n");
		return -1;
	}

	ctnl_register_handler(cpi->cth, &new_h);
	ctnl_register_handler(cpi->cth, &destroy_h);

	cpi->ctnl_fd.fd = ctnl_fd(cpi->cth);
	cpi->ctnl_fd.cb = &read_cb_ctnl;
	cpi->ctnl_fd.data = cpi;

	ulogd_register_fd(&cpi->ctnl_fd);
	
	return &cpi->upi;
}


static int destructor_ctnl(struct ulogd_pluginstance *pi)
{
	struct ctnl_pluginstance *cpi = (void *) pi;

	if (ctnl_close(&cpi->cth) < 0) {
		print("error2\n");
		return -1;
	}

	return 0;
}

static struct ulogd_key ctnl_okeys[] = {
	{
		.type 	= ULOGD_RET_IPADDR,
		.flags 	= ULOGD_RETF_NONE,
		.key	= "ip.saddr",
		.ipfix	= { },
	},
	{
		.type	= ULOGD_RET_IPADDR,
		.flags	= ULOGD_RETF_NONE,
		.key	= "ip.daddr",
		.ipfix	= { },
	},
	{
		.type	= ULOGD_RET_UINT8,
		.flags	= ULOGD_RETF_NONE,
		.key	= "ip.protocol",
		.ipfix	= { },
	},
	{
		.type	= ULOGD_RET_UINT16,
		.flags 	= ULOGD_RETF_NONE,
		.key	= "tcp.sport",
		.ipfix	= {
			.vendor 	= IPFIX_VENDOR_IETF,
			.field_id 	= 7,
		},
	},
	{
		.type	= ULOGD_RET_UINT16,
		.flags 	= ULOGD_RETF_NONE,
		.key	= "tcp.dport",
		.ipfix	= {
			.vendor 	= IPFIX_VENDOR_IETF,
			.field_id 	= 11,
		},
	},
	{
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "raw.pktlen",
		.ipfix = { 
			.vendor 	= IPFIX_VENDOR_IETF,
			.field_id 	= 1,
		},
	},
	{
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "raw.pktcount",
		.ipfix = { 
			.vendor 	= IPFIX_VENDOR_IETF,
			.field_id 	= 2,
		},
	},

};

static struct ulogd_plugin ctnl_plugin = {
	.name = "CTNL",
	.input = {
		.type = ULOGD_DTYPE_SOURCE,
	},
	.output = {
		.keys = &ctnl_okeys,
		.num_keys = ARRAY_SIZE(ctnl_okeys),
		.type = ULOGD_DTYPE_FLOW,
	},
	.config_kset 	= ,
	.interp 	= ,
	.configure	=
	.start		= &constructor_ctnl,
	.stop		= &destructor_ctnl,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	ulogd_register_plugin(&ctnl_plugin);
}

