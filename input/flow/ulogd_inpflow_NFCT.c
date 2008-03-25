/* ulogd_input_CTNL.c, Version $Revision$
 *
 * ulogd input plugin for ctnetlink
 *
 * (C) 2005 by Harald Welte <laforge@netfilter.org>
 * (C) 2008 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation
 *
 * 10 Jan 2005, Christian Hentschel <chentschel@people.netfilter.org>
 *      Added timestamp accounting support of the conntrack entries,
 *      reworked by Harald Welte.
 *
 * TODO:
 * 	- add nanosecond-accurate packet receive timestamp of event-changing
 * 	  packets to {ip,nf}_conntrack_netlink, so we can have accurate IPFIX
 *	  flowStart / flowEnd NanoSeconds.
 *	- if using preallocated data structure, get rid of all list heads and
 *	  use per-bucket arrays instead.
 *	- SIGHUP for reconfiguration without loosing hash table contents, but
 *	  re-read of config and reallocation / rehashing of table, if required
 *	- Split hashtable code into separate [filter] plugin, so we can run 
 * 	  small non-hashtable ulogd installations on the firewall boxes, send
 * 	  the messages via IPFX to one aggregator who then runs ulogd with a 
 * 	  network wide connection hash table.
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <sys/time.h>
#include <time.h>
#include <ulogd/linuxlist.h>

#include <ulogd/ulogd.h>
#include <ulogd/timer.h>
#include <ulogd/ipfix_protocol.h>

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

typedef enum TIMES_ { START, STOP, __TIME_MAX } TIMES;
 
struct ct_timestamp {
	struct llist_head list;
	struct timeval time[__TIME_MAX];
	int id;
};

struct ct_htable {
	struct llist_head *buckets;
	int num_buckets;
	int prealloc;
	struct llist_head idle;
	struct ct_timestamp *ts;
};

struct nfct_pluginstance {
	struct nfct_handle *cth;
	struct ulogd_fd nfct_fd;
	struct ulogd_timer timer;
	struct ct_htable *ct_active;
};

#define HTABLE_SIZE	(8192)
#define MAX_ENTRIES	(4 * HTABLE_SIZE)

static struct config_keyset nfct_kset = {
	.num_ces = 5,
	.ces = {
		{
			.key	 = "pollinterval",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 0,
		},
		{
			.key	 = "hash_enable",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 1,
		},
		{
			.key	 = "hash_prealloc",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 1,
		},
		{
			.key	 = "hash_buckets",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = HTABLE_SIZE,
		},
		{
			.key	 = "hash_max_entries",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = MAX_ENTRIES,
		},
	},
};
#define pollint_ce(x)	(x->ces[0])
#define usehash_ce(x)	(x->ces[1])
#define prealloc_ce(x)	(x->ces[2])
#define buckets_ce(x)	(x->ces[3])
#define maxentries_ce(x) (x->ces[4])

enum nfct_keys {
	NFCT_ORIG_IP_SADDR = 0,
	NFCT_ORIG_IP_DADDR,
	NFCT_ORIG_IP_PROTOCOL,
	NFCT_ORIG_L4_SPORT,
	NFCT_ORIG_L4_DPORT,
	NFCT_ORIG_RAW_PKTLEN,
	NFCT_ORIG_RAW_PKTCOUNT,
	NFCT_REPLY_IP_SADDR,
	NFCT_REPLY_IP_DADDR,
	NFCT_REPLY_IP_PROTOCOL,
	NFCT_REPLY_L4_SPORT,
	NFCT_REPLY_L4_DPORT,
	NFCT_REPLY_RAW_PKTLEN,
	NFCT_REPLY_RAW_PKTCOUNT,
	NFCT_ICMP_CODE,
	NFCT_ICMP_TYPE,
	NFCT_CT_MARK,
	NFCT_CT_ID,
	NFCT_FLOW_START_SEC,
	NFCT_FLOW_START_USEC,
	NFCT_FLOW_END_SEC,
	NFCT_FLOW_END_USEC,
};

static struct ulogd_key nfct_okeys[] = {
	{
		.type 	= ULOGD_RET_IPADDR,
		.flags 	= ULOGD_RETF_NONE,
		.name	= "orig.ip.saddr",
		.ipfix	= { 
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_sourceIPv4Address,
		},
	},
	{
		.type	= ULOGD_RET_IPADDR,
		.flags	= ULOGD_RETF_NONE,
		.name	= "orig.ip.daddr",
		.ipfix	= {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_destinationIPv4Address,
		},
	},
	{
		.type	= ULOGD_RET_UINT8,
		.flags	= ULOGD_RETF_NONE,
		.name	= "orig.ip.protocol",
		.ipfix	= { 
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_protocolIdentifier,
		},
	},
	{
		.type	= ULOGD_RET_UINT16,
		.flags 	= ULOGD_RETF_NONE,
		.name	= "orig.l4.sport",
		.ipfix	= {
			.vendor 	= IPFIX_VENDOR_IETF,
			.field_id 	= IPFIX_sourceTransportPort,
		},
	},
	{
		.type	= ULOGD_RET_UINT16,
		.flags 	= ULOGD_RETF_NONE,
		.name	= "orig.l4.dport",
		.ipfix	= {
			.vendor 	= IPFIX_VENDOR_IETF,
			.field_id 	= IPFIX_destinationTransportPort,
		},
	},
	{
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_RETF_NONE,
		.name	= "orig.raw.pktlen",
		.ipfix	= { 
			.vendor 	= IPFIX_VENDOR_IETF,
			.field_id 	= IPFIX_octetTotalCount,
			/* FIXME: this could also be octetDeltaCount */
		},
	},
	{
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_RETF_NONE,
		.name	= "orig.raw.pktcount",
		.ipfix	= { 
			.vendor 	= IPFIX_VENDOR_IETF,
			.field_id 	= IPFIX_packetTotalCount,
			/* FIXME: this could also be packetDeltaCount */
		},
	},
	{
		.type 	= ULOGD_RET_IPADDR,
		.flags 	= ULOGD_RETF_NONE,
		.name	= "reply.ip.saddr",
		.ipfix	= { 
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_sourceIPv4Address,
		},
	},
	{
		.type	= ULOGD_RET_IPADDR,
		.flags	= ULOGD_RETF_NONE,
		.name	= "reply.ip.daddr",
		.ipfix	= {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_destinationIPv4Address,
		},
	},
	{
		.type	= ULOGD_RET_UINT8,
		.flags	= ULOGD_RETF_NONE,
		.name	= "reply.ip.protocol",
		.ipfix	= { 
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_protocolIdentifier,
		},
	},
	{
		.type	= ULOGD_RET_UINT16,
		.flags 	= ULOGD_RETF_NONE,
		.name	= "reply.l4.sport",
		.ipfix	= {
			.vendor 	= IPFIX_VENDOR_IETF,
			.field_id 	= IPFIX_sourceTransportPort,
		},
	},
	{
		.type	= ULOGD_RET_UINT16,
		.flags 	= ULOGD_RETF_NONE,
		.name	= "reply.l4.dport",
		.ipfix	= {
			.vendor 	= IPFIX_VENDOR_IETF,
			.field_id 	= IPFIX_destinationTransportPort,
		},
	},
	{
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_RETF_NONE,
		.name	= "reply.raw.pktlen",
		.ipfix	= { 
			.vendor 	= IPFIX_VENDOR_IETF,
			.field_id 	= IPFIX_octetTotalCount,
			/* FIXME: this could also be octetDeltaCount */
		},
	},
	{
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_RETF_NONE,
		.name	= "reply.raw.pktcount",
		.ipfix	= { 
			.vendor 	= IPFIX_VENDOR_IETF,
			.field_id 	= IPFIX_packetTotalCount,
			/* FIXME: this could also be packetDeltaCount */
		},
	},
	{
		.type	= ULOGD_RET_UINT8,
		.flags	= ULOGD_RETF_NONE,
		.name	= "icmp.code",
		.ipfix	= {
			.vendor		= IPFIX_VENDOR_IETF,
			.field_id	= IPFIX_icmpCodeIPv4,
		},
	},
	{
		.type	= ULOGD_RET_UINT8,
		.flags	= ULOGD_RETF_NONE,
		.name	= "icmp.type",
		.ipfix	= {
			.vendor		= IPFIX_VENDOR_IETF,
			.field_id	= IPFIX_icmpTypeIPv4,
		},
	},
	{
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_RETF_NONE,
		.name	= "ct.mark",
		.ipfix	= {
			.vendor		= IPFIX_VENDOR_NETFILTER,
			.field_id	= IPFIX_NF_mark,
		},
	},
	{
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_RETF_NONE,
		.name	= "ct.id",
		.ipfix	= {
			.vendor		= IPFIX_VENDOR_NETFILTER,
			.field_id	= IPFIX_NF_conntrack_id,
		},
	},
	{
		.type 	= ULOGD_RET_UINT32,
		.flags 	= ULOGD_RETF_NONE,
		.name	= "flow.start.sec",
		.ipfix	= {
			.vendor		= IPFIX_VENDOR_IETF,
			.field_id	= IPFIX_flowStartSeconds,
		},
	},
	{
		.type 	= ULOGD_RET_UINT32,
		.flags 	= ULOGD_RETF_NONE,
		.name	= "flow.start.usec",
		.ipfix	= {
			.vendor		= IPFIX_VENDOR_IETF,
			.field_id	= IPFIX_flowStartMicroSeconds,
		},
	},
	{
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_RETF_NONE,
		.name	= "flow.end.sec",
		.ipfix	= {
			.vendor		= IPFIX_VENDOR_IETF,
			.field_id	= IPFIX_flowEndSeconds,
		},
	},
	{
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_RETF_NONE,
		.name	= "flow.end.usec",
		.ipfix	= {
			.vendor		= IPFIX_VENDOR_IETF,
			.field_id	= IPFIX_flowEndSeconds,
		},
	},
};

static struct ct_htable *htable_alloc(int htable_size, int prealloc)
{
	struct ct_htable *htable;
	struct ct_timestamp *ct;
	int i;

	htable = malloc(sizeof(*htable)
			+ sizeof(struct llist_head)*htable_size);
	if (!htable)
		return NULL;

	htable->buckets = (void *)htable + sizeof(*htable);
	htable->num_buckets = htable_size;
	htable->prealloc = prealloc;
	INIT_LLIST_HEAD(&htable->idle);

	for (i = 0; i < htable->num_buckets; i++)
		INIT_LLIST_HEAD(&htable->buckets[i]);
	
	if (!htable->prealloc)
		return htable;

	ct = malloc(sizeof(struct ct_timestamp)
		    * htable->num_buckets * htable->prealloc);
	if (!ct) {
		free(htable);
		return NULL;
	}

	/* save the pointer for later free()ing */
	htable->ts = ct;

	for (i = 0; i < htable->num_buckets * htable->prealloc; i++)
		llist_add(&ct[i].list, &htable->idle);

	return htable;
}

static void htable_free(struct ct_htable *htable)
{
	struct llist_head *ptr, *ptr2;
	int i;

	if (htable->prealloc) {
		/* the easy case */
		free(htable->ts);
		free(htable);

		return;
	}

	/* non-prealloc case */

	for (i = 0; i < htable->num_buckets; i++) {
		llist_for_each_safe(ptr, ptr2, &htable->buckets[i])
			free(container_of(ptr, struct ct_timestamp, list));
	}

	/* don't need to check for 'idle' list, since it is only used in
	 * the preallocated case */
}

static int ct_hash_add(struct ct_htable *htable, unsigned int id)
{
	struct ct_timestamp *ct;

	if (htable->prealloc) {
		if (llist_empty(&htable->idle)) {
			ulogd_log(ULOGD_ERROR, "Not enough ct_timestamp entries\n");
			return -1;
		}

		ct = container_of(htable->idle.next, struct ct_timestamp, list);

		ct->id = id;
		gettimeofday(&ct->time[START], NULL);

		llist_move(&ct->list, &htable->buckets[id % htable->num_buckets]);
	} else {
		ct = malloc(sizeof *ct);
		if (!ct) {
			ulogd_log(ULOGD_ERROR, "Not enough memory\n");
			return -1;
		}

		ct->id = id;
		gettimeofday(&ct->time[START], NULL);

		llist_add(&ct->list, &htable->buckets[id % htable->num_buckets]);
	}

	return 0;
}

static struct ct_timestamp *ct_hash_get(struct ct_htable *htable, uint32_t id)
{
	struct ct_timestamp *ct = NULL;
	struct llist_head *ptr;

	llist_for_each(ptr, &htable->buckets[id % htable->num_buckets]) {
		ct = container_of(ptr, struct ct_timestamp, list);
		if (ct->id == id) {
			gettimeofday(&ct->time[STOP], NULL);
			if (htable->prealloc)
				llist_move(&ct->list, &htable->idle);
			else
				free(ct);
			break;
		}
	}
	return ct;
}

static int propagate_ct(struct ulogd_pluginstance *upi,
			struct nfct_conntrack *ct,
			unsigned int flags,
			struct ct_timestamp *ts)
{
	struct ulogd_key *ret = upi->output.keys;
	int dir;
	
	dir = NFCT_DIR_ORIGINAL;
	ret[NFCT_ORIG_IP_SADDR].u.value.ui32 = htonl(ct->tuple[dir].src.v4);
	ret[NFCT_ORIG_IP_SADDR].flags |= ULOGD_RETF_VALID;

	ret[NFCT_ORIG_IP_DADDR].u.value.ui32 = htonl(ct->tuple[dir].dst.v4);
	ret[NFCT_ORIG_IP_DADDR].flags |= ULOGD_RETF_VALID;

	ret[NFCT_ORIG_IP_PROTOCOL].u.value.ui8 = ct->tuple[dir].protonum;
	ret[NFCT_ORIG_IP_PROTOCOL].flags |= ULOGD_RETF_VALID;

	switch (ct->tuple[dir].protonum) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_SCTP:
		/* FIXME: DCCP */
		ret[NFCT_ORIG_L4_SPORT].u.value.ui16 = htons(ct->tuple[dir].l4src.tcp.port);
		ret[NFCT_ORIG_L4_SPORT].flags |= ULOGD_RETF_VALID;
		ret[NFCT_ORIG_L4_DPORT].u.value.ui16 = htons(ct->tuple[dir].l4dst.tcp.port);
		ret[NFCT_ORIG_L4_DPORT].flags |= ULOGD_RETF_VALID;
		break;
	case IPPROTO_ICMP:
		ret[NFCT_ICMP_CODE].u.value.ui8 = ct->tuple[dir].l4src.icmp.code;
		ret[NFCT_ICMP_CODE].flags |= ULOGD_RETF_VALID;
		ret[NFCT_ICMP_TYPE].u.value.ui8 = ct->tuple[dir].l4src.icmp.type;
		ret[NFCT_ICMP_TYPE].flags |= ULOGD_RETF_VALID;
		break;
	}

	ret[NFCT_ORIG_RAW_PKTLEN].u.value.ui64 = ct->counters[dir].bytes;
	ret[NFCT_ORIG_RAW_PKTLEN].flags |= ULOGD_RETF_VALID;

	ret[NFCT_ORIG_RAW_PKTCOUNT].u.value.ui64 = ct->counters[dir].packets;
	ret[NFCT_ORIG_RAW_PKTCOUNT].flags |= ULOGD_RETF_VALID;

	dir = NFCT_DIR_REPLY;
	ret[NFCT_REPLY_IP_SADDR].u.value.ui32 = htonl(ct->tuple[dir].src.v4);
	ret[NFCT_REPLY_IP_SADDR].flags |= ULOGD_RETF_VALID;

	ret[NFCT_REPLY_IP_DADDR].u.value.ui32 = htonl(ct->tuple[dir].dst.v4);
	ret[NFCT_REPLY_IP_DADDR].flags |= ULOGD_RETF_VALID;

	ret[NFCT_REPLY_IP_PROTOCOL].u.value.ui8 = ct->tuple[dir].protonum;
	ret[NFCT_REPLY_IP_PROTOCOL].flags |= ULOGD_RETF_VALID;

	switch (ct->tuple[dir].protonum) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_SCTP:
		/* FIXME: DCCP */
		ret[NFCT_REPLY_L4_SPORT].u.value.ui16 = htons(ct->tuple[dir].l4src.tcp.port);
		ret[NFCT_REPLY_L4_SPORT].flags |= ULOGD_RETF_VALID;
		ret[NFCT_REPLY_L4_DPORT].u.value.ui16 = htons(ct->tuple[dir].l4dst.tcp.port);
		ret[NFCT_REPLY_L4_DPORT].flags |= ULOGD_RETF_VALID;
		break;
	case IPPROTO_ICMP:
		ret[NFCT_ICMP_CODE].u.value.ui8 = ct->tuple[dir].l4src.icmp.code;
		ret[NFCT_ICMP_CODE].flags |= ULOGD_RETF_VALID;
		ret[NFCT_ICMP_TYPE].u.value.ui8 = ct->tuple[dir].l4src.icmp.type;
		ret[NFCT_ICMP_TYPE].flags |= ULOGD_RETF_VALID;
		break;
	}

	ret[NFCT_REPLY_RAW_PKTLEN].u.value.ui64 = ct->counters[dir].bytes;
	ret[NFCT_REPLY_RAW_PKTLEN].flags |= ULOGD_RETF_VALID;

	ret[NFCT_REPLY_RAW_PKTCOUNT].u.value.ui64 = ct->counters[dir].packets;
	ret[NFCT_REPLY_RAW_PKTCOUNT].flags |= ULOGD_RETF_VALID;

	if (flags & NFCT_MARK) {
		ret[NFCT_CT_MARK].u.value.ui32 = ct->mark;
		ret[NFCT_CT_MARK].flags |= ULOGD_RETF_VALID;
	}

	if (flags & NFCT_ID) {
		ret[NFCT_CT_ID].u.value.ui32 = ct->id;
		ret[NFCT_CT_ID].flags |= ULOGD_RETF_VALID;
	}

	if (ts) {
		ret[NFCT_FLOW_START_SEC].u.value.ui32 = ts->time[START].tv_sec;
		ret[NFCT_FLOW_START_SEC].flags |= ULOGD_RETF_VALID;
		ret[NFCT_FLOW_START_USEC].u.value.ui32 = ts->time[START].tv_usec;
		ret[NFCT_FLOW_START_USEC].flags |= ULOGD_RETF_VALID;
		ret[NFCT_FLOW_END_SEC].u.value.ui32 = ts->time[STOP].tv_sec;
		ret[NFCT_FLOW_END_SEC].flags |= ULOGD_RETF_VALID;
		ret[NFCT_FLOW_END_USEC].u.value.ui32 = ts->time[STOP].tv_usec;
		ret[NFCT_FLOW_END_USEC].flags |= ULOGD_RETF_VALID;
	}

	ulogd_propagate_results(upi);

	return 0;
}

/* XXX: pollinterval needs a different handler */
static int event_handler(void *arg, unsigned int flags, int type,
			 void *data)
{
	struct nfct_conntrack *ct = arg;
	struct ulogd_pluginstance *upi = data;
	struct ulogd_pluginstance *npi = NULL;
	struct nfct_pluginstance *cpi = 
				(struct nfct_pluginstance *) upi->private;
	int ret = 0;

	if (type == NFCT_MSG_NEW) {
		if (usehash_ce(upi->config_kset).u.value != 0)
			ct_hash_add(cpi->ct_active, ct->id);
	} else if (type == NFCT_MSG_DESTROY) {
		struct ct_timestamp *ts = NULL;

		if (usehash_ce(upi->config_kset).u.value != 0)
			ts = ct_hash_get(cpi->ct_active, ct->id);

		/* since we support the re-use of one instance in
		 * several different stacks, we duplicate the message
		 * to let them know */
		llist_for_each_entry(npi, &upi->plist, plist) {
			ret = propagate_ct(npi, ct, flags, ts);
			if (ret != 0)
				return ret;
		}
		return propagate_ct(upi, ct, flags, ts);
	}
	return 0;
}

static int read_cb_nfct(int fd, unsigned int what, void *param)
{
	struct nfct_pluginstance *cpi = (struct nfct_pluginstance *) param;

	if (!(what & ULOGD_FD_READ))
		return 0;

	/* FIXME: implement this */
	nfct_event_conntrack(cpi->cth);
	return 0;
}

static int get_ctr_zero(struct ulogd_pluginstance *upi)
{
	struct nfct_pluginstance *cpi = 
			(struct nfct_pluginstance *)upi->private;

	return nfct_dump_conntrack_table_reset_counters(cpi->cth, AF_INET);
}

static void getctr_timer_cb(struct ulogd_timer *t, void *data)
{
	struct ulogd_pluginstance *upi = data;
	struct nfct_pluginstance *cpi = 
			(struct nfct_pluginstance *)upi->private;

	get_ctr_zero(upi);
	ulogd_add_timer(&cpi->timer, pollint_ce(upi->config_kset).u.value);
}

static int configure_nfct(struct ulogd_pluginstance *upi,
			  struct ulogd_pluginstance_stack *stack)
{
	struct nfct_pluginstance *cpi = 
			(struct nfct_pluginstance *)upi->private;
	int ret;
	
	ret = config_parse_file(upi->id, upi->config_kset);
	if (ret < 0)
		return ret;

	ulogd_init_timer(&cpi->timer, upi, getctr_timer_cb);
	if (pollint_ce(upi->config_kset).u.value != 0)
		ulogd_add_timer(&cpi->timer,
				pollint_ce(upi->config_kset).u.value);

	return 0;
}

static int constructor_nfct(struct ulogd_pluginstance *upi)
{
	struct nfct_pluginstance *cpi = 
			(struct nfct_pluginstance *)upi->private;
	int prealloc;

	/* FIXME: make eventmask configurable */
	cpi->cth = nfct_open(NFNL_SUBSYS_CTNETLINK, NF_NETLINK_CONNTRACK_NEW|
			     NF_NETLINK_CONNTRACK_DESTROY);
	if (!cpi->cth) {
		ulogd_log(ULOGD_FATAL, "error opening ctnetlink\n");
		return -1;
	}

	nfct_register_callback(cpi->cth, &event_handler, upi);

	cpi->nfct_fd.fd = nfct_fd(cpi->cth);
	cpi->nfct_fd.cb = &read_cb_nfct;
	cpi->nfct_fd.data = cpi;
	cpi->nfct_fd.when = ULOGD_FD_READ;

	ulogd_register_fd(&cpi->nfct_fd);

	if (prealloc_ce(upi->config_kset).u.value != 0)
		prealloc = maxentries_ce(upi->config_kset).u.value / 
				buckets_ce(upi->config_kset).u.value;
	else
		prealloc = 0;

	if (usehash_ce(upi->config_kset).u.value != 0) {
		cpi->ct_active = htable_alloc(buckets_ce(upi->config_kset).u.value,
					      prealloc);
		if (!cpi->ct_active) {
			ulogd_log(ULOGD_FATAL, "error allocating hash\n");
			nfct_close(cpi->cth);
			return -1;
		}
	}
	
	return 0;
}

static int destructor_nfct(struct ulogd_pluginstance *pi)
{
	struct nfct_pluginstance *cpi = (void *) pi;
	int rc;
	
	htable_free(cpi->ct_active);

	rc = nfct_close(cpi->cth);
	if (rc < 0)
		return rc;

	return 0;
}

static void signal_nfct(struct ulogd_pluginstance *pi, int signal)
{
	switch (signal) {
	case SIGUSR2:
		get_ctr_zero(pi);
		break;
	}
}

static struct ulogd_plugin nfct_plugin = {
	.name = "NFCT",
	.input = {
		.type = ULOGD_DTYPE_SOURCE,
	},
	.output = {
		.keys = nfct_okeys,
		.num_keys = ARRAY_SIZE(nfct_okeys),
		.type = ULOGD_DTYPE_FLOW,
	},
	.config_kset 	= &nfct_kset,
	.interp 	= NULL,
	.configure	= &configure_nfct,
	.start		= &constructor_nfct,
	.stop		= &destructor_nfct,
	.signal		= &signal_nfct,
	.priv_size	= sizeof(struct nfct_pluginstance),
	.version	= ULOGD_VERSION,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	ulogd_register_plugin(&nfct_plugin);
}

