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
 * 11 May 2008, Pablo Neira Ayuso <pablo@netfilter.org>
 * 	Use a generic hashtable to store the existing flows
 * 	Add netlink overrun handling
 *
 * TODO:
 * 	- add nanosecond-accurate packet receive timestamp of event-changing
 * 	  packets to {ip,nf}_conntrack_netlink, so we can have accurate IPFIX
 *	  flowStart / flowEnd NanoSeconds.
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
#include <ulogd/jhash.h>
#include <ulogd/hash.h>

#include <ulogd/ulogd.h>
#include <ulogd/timer.h>
#include <ulogd/ipfix_protocol.h>

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

typedef enum TIMES_ { START, STOP, __TIME_MAX } TIMES;

struct ct_timestamp {
	struct timeval time[__TIME_MAX];
	struct nf_conntrack *ct;
};

struct nfct_pluginstance {
	struct nfct_handle *cth;
	struct nfct_handle *ovh;	/* overrun handler */
	struct nfct_handle *pgh;	/* purge handler */
	struct ulogd_fd nfct_fd;
	struct ulogd_fd nfct_ov;
	struct ulogd_timer timer;
	struct ulogd_timer ov_timer;	/* overrun retry timer */
	struct hashtable *ct_active;
	int nlbufsiz;			/* current netlink buffer size */
};

#define HTABLE_SIZE	(8192)
#define MAX_ENTRIES	(4 * HTABLE_SIZE)
#define EVENT_MASK	NF_NETLINK_CONNTRACK_NEW | NF_NETLINK_CONNTRACK_DESTROY

static struct config_keyset nfct_kset = {
	.num_ces = 7,
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
		{
			.key	 = "event_mask",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = EVENT_MASK,
		},
		{
			.key	 = "netlink_socket_buffer_size",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 0,
		},
		{
			.key	 = "netlink_socket_buffer_maxsize",
			.type	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 0,
		},
	},
};
#define pollint_ce(x)	(x->ces[0])
#define usehash_ce(x)	(x->ces[1])
#define buckets_ce(x)	(x->ces[2])
#define maxentries_ce(x) (x->ces[3])
#define eventmask_ce(x) (x->ces[4])
#define nlsockbufsize_ce(x) (x->ces[5])
#define nlsockbufmaxsize_ce(x) (x->ces[6])

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
	NFCT_CT_EVENT,
	NFCT_FLOW_START_SEC,
	NFCT_FLOW_START_USEC,
	NFCT_FLOW_END_SEC,
	NFCT_FLOW_END_USEC,
	NFCT_OOB_FAMILY,
	NFCT_OOB_PROTOCOL,
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
		.type	= ULOGD_RET_UINT32,
		.flags	= ULOGD_RETF_NONE,
		.name	= "ct.event",
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
	{
		.type	= ULOGD_RET_UINT8,
		.flags	= ULOGD_RETF_NONE,
		.name	= "oob.family",
	},
	{
		.type	= ULOGD_RET_UINT8,
		.flags	= ULOGD_RETF_NONE,
		.name	= "oob.protocol",
	},
};

static uint32_t __hash4(const struct nf_conntrack *ct, struct hashtable *table)
{
	unsigned int a, b;

	a = jhash(nfct_get_attr(ct, ATTR_ORIG_IPV4_SRC), sizeof(uint32_t),
		  ((nfct_get_attr_u8(ct, ATTR_ORIG_L3PROTO) << 16) |
		   (nfct_get_attr_u8(ct, ATTR_ORIG_L4PROTO))));

	b = jhash(nfct_get_attr(ct, ATTR_ORIG_IPV4_DST), sizeof(uint32_t),
		  ((nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC) << 16) |
		   (nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST))));

	/*
	 * Instead of returning hash % table->hashsize (implying a divide)
	 * we return the high 32 bits of the (hash * table->hashsize) that will
	 * give results between [0 and hashsize-1] and same hash distribution,
	 * but using a multiply, less expensive than a divide. See:
	 * http://www.mail-archive.com/netdev@vger.kernel.org/msg56623.html
	 */
	return ((uint64_t)jhash_2words(a, b, 0) * table->hashsize) >> 32;
}

static uint32_t __hash6(const struct nf_conntrack *ct, struct hashtable *table)
{
	unsigned int a, b;

	a = jhash(nfct_get_attr(ct, ATTR_ORIG_IPV6_SRC), sizeof(uint32_t)*4,
		  ((nfct_get_attr_u8(ct, ATTR_ORIG_L3PROTO) << 16) |
		   (nfct_get_attr_u8(ct, ATTR_ORIG_L4PROTO))));

	b = jhash(nfct_get_attr(ct, ATTR_ORIG_IPV6_DST), sizeof(uint32_t)*4,
		  ((nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC) << 16) |
		   (nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST))));

	return ((uint64_t)jhash_2words(a, b, 0) * table->hashsize) >> 32;
}

static uint32_t hash(const void *data, struct hashtable *table)
{
	int ret = 0;
	const struct ct_timestamp *ts = data;

	switch(nfct_get_attr_u8(ts->ct, ATTR_L3PROTO)) {
		case AF_INET:
			ret = __hash4(ts->ct, table);
			break;
		case AF_INET6:
			ret = __hash6(ts->ct, table);
			break;
		default:
			break;
	}

	return ret;
}

static int compare(const void *data1, const void *data2)
{
	const struct ct_timestamp *u1 = data1;
	const struct ct_timestamp *u2 = data2;

	return nfct_cmp(u1->ct, u2->ct, NFCT_CMP_ORIG | NFCT_CMP_REPL);
}

static int propagate_ct(struct ulogd_pluginstance *upi,
			struct nf_conntrack *ct,
			int type,
			struct ct_timestamp *ts)
{
	struct ulogd_key *ret = upi->output.keys;
	
	ret[NFCT_CT_EVENT].u.value.ui32 = type;
	ret[NFCT_CT_EVENT].flags |= ULOGD_RETF_VALID;

	ret[NFCT_OOB_FAMILY].u.value.ui8 = nfct_get_attr_u8(ct, ATTR_L3PROTO);
	ret[NFCT_OOB_FAMILY].flags |= ULOGD_RETF_VALID;
	/* FIXME */
	ret[NFCT_OOB_PROTOCOL].u.value.ui8 = 0;
	ret[NFCT_OOB_PROTOCOL].flags |= ULOGD_RETF_VALID;

	switch (nfct_get_attr_u8(ct, ATTR_L3PROTO)) {
	case AF_INET:
		ret[NFCT_ORIG_IP_SADDR].u.value.ui32 =
			nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_SRC);
		ret[NFCT_ORIG_IP_SADDR].flags |= ULOGD_RETF_VALID;

		ret[NFCT_ORIG_IP_DADDR].u.value.ui32 =
			nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_DST);
		ret[NFCT_ORIG_IP_DADDR].flags |= ULOGD_RETF_VALID;

		ret[NFCT_REPLY_IP_SADDR].u.value.ui32 =
			nfct_get_attr_u32(ct, ATTR_REPL_IPV4_SRC);
		ret[NFCT_REPLY_IP_SADDR].flags |= ULOGD_RETF_VALID;

		ret[NFCT_REPLY_IP_DADDR].u.value.ui32 =
			nfct_get_attr_u32(ct, ATTR_REPL_IPV4_DST);
		ret[NFCT_REPLY_IP_DADDR].flags |= ULOGD_RETF_VALID;

		break;
	case AF_INET6:
		memcpy(ret[NFCT_ORIG_IP_SADDR].u.value.ui128,
		       nfct_get_attr(ct, ATTR_ORIG_IPV6_SRC),
		       sizeof(int32_t) * 4);
		ret[NFCT_ORIG_IP_SADDR].flags |= ULOGD_RETF_VALID;

		memcpy(ret[NFCT_ORIG_IP_DADDR].u.value.ui128,
		       nfct_get_attr(ct, ATTR_ORIG_IPV6_DST),
		       sizeof(int32_t) * 4);
		ret[NFCT_ORIG_IP_DADDR].flags |= ULOGD_RETF_VALID;

		memcpy(ret[NFCT_REPLY_IP_SADDR].u.value.ui128,
		       nfct_get_attr(ct, ATTR_REPL_IPV6_SRC),
		       sizeof(int32_t) * 4);
		ret[NFCT_REPLY_IP_SADDR].flags |= ULOGD_RETF_VALID;

		memcpy(ret[NFCT_REPLY_IP_DADDR].u.value.ui128,
		       nfct_get_attr(ct, ATTR_REPL_IPV6_DST),
		       sizeof(int32_t) * 4);
		ret[NFCT_REPLY_IP_DADDR].flags |= ULOGD_RETF_VALID;

		break;
	default:
		ulogd_log(ULOGD_NOTICE, "Unknown protocol family (%d)\n",
			  nfct_get_attr_u8(ct, ATTR_L3PROTO));
	}
	ret[NFCT_ORIG_IP_PROTOCOL].u.value.ui8 =
		nfct_get_attr_u8(ct, ATTR_ORIG_L4PROTO);
	ret[NFCT_ORIG_IP_PROTOCOL].flags |= ULOGD_RETF_VALID;

	ret[NFCT_REPLY_IP_PROTOCOL].u.value.ui8 =
		nfct_get_attr_u8(ct, ATTR_REPL_L4PROTO);
	ret[NFCT_REPLY_IP_PROTOCOL].flags |= ULOGD_RETF_VALID;

	switch (nfct_get_attr_u8(ct, ATTR_ORIG_L4PROTO)) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_UDPLITE:
	case IPPROTO_SCTP:
	case IPPROTO_DCCP:
		ret[NFCT_ORIG_L4_SPORT].u.value.ui16 =
			htons(nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC));
		ret[NFCT_ORIG_L4_SPORT].flags |= ULOGD_RETF_VALID;

		ret[NFCT_ORIG_L4_DPORT].u.value.ui16 =
			htons(nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST));
		ret[NFCT_ORIG_L4_DPORT].flags |= ULOGD_RETF_VALID;
		break;
	case IPPROTO_ICMP:
		ret[NFCT_ICMP_CODE].u.value.ui8 =
			nfct_get_attr_u8(ct, ATTR_ICMP_CODE);
		ret[NFCT_ICMP_CODE].flags |= ULOGD_RETF_VALID;

		ret[NFCT_ICMP_TYPE].u.value.ui8 =
			nfct_get_attr_u8(ct, ATTR_ICMP_TYPE);
		ret[NFCT_ICMP_TYPE].flags |= ULOGD_RETF_VALID;
		break;
	}

	switch (nfct_get_attr_u8(ct, ATTR_REPL_L4PROTO)) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_UDPLITE:
	case IPPROTO_SCTP:
	case IPPROTO_DCCP:
		ret[NFCT_REPLY_L4_SPORT].u.value.ui16 =
			htons(nfct_get_attr_u16(ct, ATTR_REPL_PORT_SRC));
		ret[NFCT_REPLY_L4_SPORT].flags |= ULOGD_RETF_VALID;

		ret[NFCT_REPLY_L4_DPORT].u.value.ui16 =
			htons(nfct_get_attr_u16(ct, ATTR_REPL_PORT_DST));
		ret[NFCT_REPLY_L4_DPORT].flags |= ULOGD_RETF_VALID;
	}

	ret[NFCT_ORIG_RAW_PKTLEN].u.value.ui32 =
		nfct_get_attr_u32(ct, ATTR_ORIG_COUNTER_BYTES);
	ret[NFCT_ORIG_RAW_PKTLEN].flags |= ULOGD_RETF_VALID;

	ret[NFCT_ORIG_RAW_PKTCOUNT].u.value.ui32 =
		nfct_get_attr_u32(ct, ATTR_ORIG_COUNTER_PACKETS);
	ret[NFCT_ORIG_RAW_PKTCOUNT].flags |= ULOGD_RETF_VALID;

	ret[NFCT_REPLY_RAW_PKTLEN].u.value.ui32 =
		nfct_get_attr_u32(ct, ATTR_REPL_COUNTER_BYTES);;
	ret[NFCT_REPLY_RAW_PKTLEN].flags |= ULOGD_RETF_VALID;

	ret[NFCT_REPLY_RAW_PKTCOUNT].u.value.ui32 =
		nfct_get_attr_u32(ct, ATTR_REPL_COUNTER_PACKETS);
	ret[NFCT_REPLY_RAW_PKTCOUNT].flags |= ULOGD_RETF_VALID;

	ret[NFCT_CT_MARK].u.value.ui32 = nfct_get_attr_u32(ct, ATTR_MARK);
	ret[NFCT_CT_MARK].flags |= ULOGD_RETF_VALID;

	ret[NFCT_CT_ID].u.value.ui32 = nfct_get_attr_u32(ct, ATTR_ID);
	ret[NFCT_CT_ID].flags |= ULOGD_RETF_VALID;

	if (ts) {
		if (ts->time[START].tv_sec) {
			ret[NFCT_FLOW_START_SEC].u.value.ui32 = 
				ts->time[START].tv_sec;
			ret[NFCT_FLOW_START_SEC].flags |= ULOGD_RETF_VALID;

			ret[NFCT_FLOW_START_USEC].u.value.ui32 =
				ts->time[START].tv_usec;
			ret[NFCT_FLOW_START_USEC].flags |= ULOGD_RETF_VALID;
		}
		if (ts->time[STOP].tv_sec) {
			ret[NFCT_FLOW_END_SEC].u.value.ui32 =
				ts->time[STOP].tv_sec;
			ret[NFCT_FLOW_END_SEC].flags |= ULOGD_RETF_VALID;

			ret[NFCT_FLOW_END_USEC].u.value.ui32 =
				ts->time[STOP].tv_usec;
			ret[NFCT_FLOW_END_USEC].flags |= ULOGD_RETF_VALID;
		}
	}

	ulogd_propagate_results(upi);

	return 0;
}

static void
do_propagate_ct(struct ulogd_pluginstance *upi,
		struct nf_conntrack *ct,
		int type,
		struct ct_timestamp *ts)
{
	struct ulogd_pluginstance *npi = NULL;

	/* since we support the re-use of one instance in
	 * several different stacks, we duplicate the message
	 * to let them know */
	llist_for_each_entry(npi, &upi->plist, plist) {
		if (propagate_ct(npi, ct, type, ts) != 0)
			break;
	}

	propagate_ct(upi, ct, type, ts);
}

/* XXX: pollinterval needs a different handler */
static int event_handler(enum nf_conntrack_msg_type type,
			 struct nf_conntrack *ct,
			 void *data)
{
	struct ulogd_pluginstance *upi = data;
	struct nfct_pluginstance *cpi = 
				(struct nfct_pluginstance *) upi->private;
	struct ct_timestamp *ts = NULL;
	struct ct_timestamp tmp = {
		.ct = ct,
	};

	if (!usehash_ce(upi->config_kset).u.value) {
		switch(type) {
		case NFCT_T_NEW:
			gettimeofday(&tmp.time[START], NULL);
			tmp.time[STOP].tv_sec = 0;
			tmp.time[STOP].tv_usec = 0;
			break;
		case NFCT_T_DESTROY:
			gettimeofday(&tmp.time[STOP], NULL);
			tmp.time[START].tv_sec = 0;
			tmp.time[START].tv_usec = 0;
			break;
		default:
			ulogd_log(ULOGD_NOTICE, "unsupported message type\n");
			break;
		}
		do_propagate_ct(upi, ct, type, &tmp);
		return NFCT_CB_CONTINUE;
	}

	switch(type) {
	case NFCT_T_NEW:
		ts = hashtable_add(cpi->ct_active, &tmp);
		gettimeofday(&ts->time[START], NULL);
		return NFCT_CB_STOLEN;
	case NFCT_T_UPDATE:
		ts = hashtable_get(cpi->ct_active, &tmp);
		if (ts)
			nfct_copy(ts->ct, ct, NFCT_CP_META);
		else {
			ts = hashtable_add(cpi->ct_active, &tmp);
			gettimeofday(&ts->time[START], NULL);
			return NFCT_CB_STOLEN;
		}
		break;
	case NFCT_T_DESTROY:
		ts = hashtable_get(cpi->ct_active, &tmp);
		if (ts) {
			gettimeofday(&ts->time[STOP], NULL);
			do_propagate_ct(upi, ct, type, ts);
		} else {
			gettimeofday(&tmp.time[STOP], NULL);
			tmp.time[START].tv_sec = 0;
			tmp.time[START].tv_usec = 0;
			do_propagate_ct(upi, ct, type, &tmp);
		}

		if (ts) {
			hashtable_del(cpi->ct_active, ts);
			free(ts->ct);
		}
		break;
	default:
		ulogd_log(ULOGD_NOTICE, "unknown netlink message type\n");
		break;
	}

	return NFCT_CB_CONTINUE;
}

static int setnlbufsiz(struct ulogd_pluginstance *upi, int size)
{
	struct nfct_pluginstance *cpi =
			(struct nfct_pluginstance *)upi->private;

	if (size < nlsockbufmaxsize_ce(upi->config_kset).u.value) {
		cpi->nlbufsiz = nfnl_rcvbufsiz(nfct_nfnlh(cpi->cth), size);
		return 1;
	}

	ulogd_log(ULOGD_NOTICE, "Maximum buffer size (%d) in NFCT has been "
				"reached. Please, consider rising "
				"`netlink_socket_buffer_size` and "
				"`netlink_socket_buffer_maxsize` "
				"clauses.\n", cpi->nlbufsiz);
	return 0;
}

static int read_cb_nfct(int fd, unsigned int what, void *param)
{
	struct nfct_pluginstance *cpi = (struct nfct_pluginstance *) param;
	struct ulogd_pluginstance *upi = container_of(param,
						      struct ulogd_pluginstance,
						      private);

	if (!(what & ULOGD_FD_READ))
		return 0;

	if (nfct_catch(cpi->cth) == -1) {
		if (errno == ENOBUFS) {
			int family = AF_UNSPEC;

			if (nlsockbufmaxsize_ce(upi->config_kset).u.value) {
				int s = cpi->nlbufsiz * 2;
				if (setnlbufsiz(upi, s)) {
					ulogd_log(ULOGD_NOTICE,
						  "We are losing events, "
						  "increasing buffer size "
						  "to %d\n", cpi->nlbufsiz);
				}
			} else {
				ulogd_log(ULOGD_NOTICE,
					  "We are losing events. Please, "
					  "consider using the clauses "
					  "`netlink_socket_buffer_size' and "
					  "`netlink_socket_buffer_maxsize'\n");
			}
			
			/* internal hash can deal with refresh */
			if (usehash_ce(upi->config_kset).u.value != 0) {
				nfct_send(cpi->ovh, NFCT_Q_DUMP, &family);
				/* TODO: configurable retry timer */
				ulogd_add_timer(&cpi->ov_timer, 2);
			}
		}
	}

	return 0;
}

static int do_purge(void *data1, void *data2)
{
	int ret;
	struct ulogd_pluginstance *upi = data1;
	struct ct_timestamp *ts = data2;
	struct nfct_pluginstance *cpi =
				(struct nfct_pluginstance *) upi->private;

	/* if it is not in kernel anymore, purge it */
	ret = nfct_query(cpi->pgh, NFCT_Q_GET, ts->ct);
	if (ret == -1 && errno == ENOENT) {
		do_propagate_ct(upi, ts->ct, NFCT_T_DESTROY, ts);
		hashtable_del(cpi->ct_active, ts);
		free(ts->ct);
	}

	return 0;
}

static int overrun_handler(enum nf_conntrack_msg_type type,
			   struct nf_conntrack *ct,
			   void *data)
{
	struct ulogd_pluginstance *upi = data;
	struct nfct_pluginstance *cpi =
				(struct nfct_pluginstance *) upi->private;
	struct ct_timestamp *ts, tmp = {
		.ct = ct,
	};

	/* if it does not exist, add it */
	if (!hashtable_get(cpi->ct_active, &tmp)) {
		ts = hashtable_add(cpi->ct_active, &tmp);
		gettimeofday(&ts->time[START], NULL); /* do our best here */
		return NFCT_CB_STOLEN;
	}

	return NFCT_CB_CONTINUE;
}

static int read_cb_ovh(int fd, unsigned int what, void *param)
{
	struct nfct_pluginstance *cpi = (struct nfct_pluginstance *) param;
	struct ulogd_pluginstance *upi = container_of(param,
						      struct ulogd_pluginstance,
						      private);

	if (!(what & ULOGD_FD_READ))
		return 0;

	/* handle the resync request, update our hashtable */
	if (nfct_catch(cpi->ovh) == -1) {
		/* enobufs in the overrun buffer? very rare */
		if (errno == ENOBUFS) {
			int family = AF_UNSPEC;

			nfct_send(cpi->ovh, NFCT_Q_DUMP, &family);
			/* TODO: configurable retry timer */
			ulogd_add_timer(&cpi->ov_timer, 2);
		}
	}

	/* purge unexistent entries */
	hashtable_iterate(cpi->ct_active, upi, do_purge);

	return 0;
}

static int get_ctr_zero(struct ulogd_pluginstance *upi)
{
	int family = 0; /* any */
	struct nfct_pluginstance *cpi = 
			(struct nfct_pluginstance *)upi->private;

	return nfct_query(cpi->cth, NFCT_Q_DUMP_RESET, &family);
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

static void overrun_timeout(struct ulogd_timer *a, void *data)
{
	int family = AF_UNSPEC;
	struct ulogd_pluginstance *upi = data;
	struct nfct_pluginstance *cpi =
			(struct nfct_pluginstance *)upi->private;

	nfct_send(cpi->ovh, NFCT_Q_DUMP, &family);
	/* TODO: configurable retry timer */
	ulogd_add_timer(&cpi->ov_timer, 2);
}

static int constructor_nfct(struct ulogd_pluginstance *upi)
{
	struct nfct_pluginstance *cpi = 
			(struct nfct_pluginstance *)upi->private;

	cpi->cth = nfct_open(NFNL_SUBSYS_CTNETLINK,
			     eventmask_ce(upi->config_kset).u.value);
	if (!cpi->cth) {
		ulogd_log(ULOGD_FATAL, "error opening ctnetlink\n");
		return -1;
	}

	nfct_callback_register(cpi->cth, NFCT_T_ALL, &event_handler, upi);

	if (nlsockbufsize_ce(upi->config_kset).u.value) {
		setnlbufsiz(upi, nlsockbufsize_ce(upi->config_kset).u.value);
		ulogd_log(ULOGD_NOTICE, "NFCT netlink buffer size has been "
					"set to %d\n", cpi->nlbufsiz);
	}

	if (usehash_ce(upi->config_kset).u.value != 0) {
		cpi->ovh = nfct_open(NFNL_SUBSYS_CTNETLINK, 0);
		if (!cpi->ovh) {
			ulogd_log(ULOGD_FATAL, "error opening ctnetlink\n");
			return -1;
		}

		nfct_callback_register(cpi->ovh, NFCT_T_ALL,
				       &overrun_handler, upi);
	}

	cpi->pgh = nfct_open(NFNL_SUBSYS_CTNETLINK, 0);
	if (!cpi->pgh) {
		ulogd_log(ULOGD_FATAL, "error opening ctnetlink\n");
		return -1;
	}

	ulogd_init_timer(&cpi->ov_timer, upi, overrun_timeout);

	cpi->nfct_fd.fd = nfct_fd(cpi->cth);
	cpi->nfct_fd.cb = &read_cb_nfct;
	cpi->nfct_fd.data = cpi;
	cpi->nfct_fd.when = ULOGD_FD_READ;

	ulogd_register_fd(&cpi->nfct_fd);

	if (usehash_ce(upi->config_kset).u.value != 0) {
		cpi->nfct_ov.fd = nfct_fd(cpi->ovh);
		cpi->nfct_ov.cb = &read_cb_ovh;
		cpi->nfct_ov.data = cpi;
		cpi->nfct_ov.when = ULOGD_FD_READ;

		ulogd_register_fd(&cpi->nfct_ov);

		cpi->ct_active =
		     hashtable_create(buckets_ce(upi->config_kset).u.value,
				      maxentries_ce(upi->config_kset).u.value,
				      sizeof(struct ct_timestamp),
				      hash,
				      compare);
		if (!cpi->ct_active) {
			ulogd_log(ULOGD_FATAL, "error allocating hash\n");
			nfct_close(cpi->cth);
			nfct_close(cpi->ovh);
			nfct_close(cpi->pgh);
			return -1;
		}
	}
	
	return 0;
}

static int destructor_nfct(struct ulogd_pluginstance *pi)
{
	struct nfct_pluginstance *cpi = (void *) pi;
	int rc;
	
	hashtable_destroy(cpi->ct_active);

	rc = nfct_close(cpi->cth);
	if (rc < 0)
		return rc;


	if (usehash_ce(pi->config_kset).u.value != 0) {
		rc = nfct_close(cpi->ovh);
		if (rc < 0)
			return rc;
	}

	rc = nfct_close(cpi->pgh);
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

