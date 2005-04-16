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

#include "libnfnetlink.h"
#include "libctnetlink.h"

struct ulogd_ctnl_pluginstance {
	struct ulogd_pluginstance upi;
	struct ctnl_handle cth;
};

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

	if (type == IPCTNL_MSG_CT_NEW && flags & NLM_F_CREATE) {
		/* FIXME: build hash table with timestamp of start of
		 * connection */
	} else if (type == IPCTNL_MSG_CT_DELETE) {
		/* We have the final count of bytes for this connection */
	}
	return 0;
}

struct ctnl_msg_handler new_h = {
	.type = IPCTNL_MSG_CT_NEW,
	.handler = event_handler,
};
struct ctnl_msg_Handler destroy_h = {
	.type = IPCTNL_MSG_CT_DELETE,
	.handler = event_handler,
};

static struct ulogd_plugin ctnl_plugin = {
	.name = "CTNL",
	.input = {
		.keys =,
		.num_keys = 1,
		.type = ULOGD_DTYPE_NULL,
	},
	.output = {
		.keys =,
		.num_keys = 1,
		.type = ULOGD_DTYPE_FLOW,
	},
	.interp = ,
	.constructor = ,
	.descructor = ,
	.config_kset = ,
};



static struct ulogd_pluginstance *constructor_ctnl(struct ulogd_plugin *pl)
{
	struct ulogd_ctnl_pluginstance *cpi = malloc(sizeof *cpi);

	if (!cpu)
		return NULL;

	memset(cpi, NULL, sizeof(*cpi));

	cpi->plugin = pl;
	cpi->input = FIXME;
	cpi->>output = FIXME;

	if (ctnl_open(&cpi->cth, NFGRP_IPV4_CT_TCP|NFGRP_IPV4_CT_UDP) < 0) {
		print("error\n");
		return NULL; 
	}

	ctnl_register_handler(&cpi->cth, &new_h);
	ctnl_register_handler(&cpi->cth, &destroy_h);
	//ctnl_event_conntrack(&cth, AF_INET);
	
	return &cpi->upi;
}


static int destructor_ctnl(struct ulogd_pluginstance *pi)
{
	struct ulogd_ctnl_pluginstance *cpi = (void *) pi;

	if (ctnl_close(&cpi->cth) < 0) {
		print("error2\n");
		return -1;
	}

	return 0;
}
		
