/* ulogd_MAC.c, Version $Revision: 1.6 $
 *
 * ulogd logging interpreter for MAC addresses, TIME, IP and TCP headers, etc.
 *
 * (C) 2000 by Harald Welte <laforge@gnumonks.org>
 * This software is released under the terms of GNU GPL
 *
 * $Id: ulogd_BASE.c,v 1.6 2000/09/26 06:25:02 laforge Exp $
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <ulogd.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/udp.h>

/***********************************************************************
 * 			Raw header
 ***********************************************************************/
static ulog_iret_t mac_rets[1] = {
	{ NULL, NULL, 0, ULOGD_RET_STRING, ULOGD_RETF_FREE, "raw.mac", NULL },
};

ulog_iret_t *_interp_mac(struct ulog_interpreter *ip, ulog_packet_msg_t *pkt)
{
	unsigned char *p;
	int i;
	char *buf;
	ulog_iret_t *ret = ip->result;
	
	if (pkt->mac_len) {
		buf = (char *) malloc(3 * pkt->mac_len + 1);
		*buf = 0;

		p = pkt->mac;
		for (i = 0; i < pkt->mac_len; i++, p++)
			sprintf(buf, "%s%02x%c", buf, *p, i==pkt->mac_len-1 ? ' ':':');
		ret[0].value.ptr = buf;
		ret[0].flags |= ULOGD_RETF_VALID;
		return ret;

	}
	return NULL;
}

/***********************************************************************
 * 			OUT OF BAND
 ***********************************************************************/

static ulog_iret_t oob_rets[] = {
	{ NULL, NULL, 0, ULOGD_RET_STRING, ULOGD_RETF_NONE, "oob.prefix", NULL },
	{ NULL, NULL, 0, ULOGD_RET_UINT32, ULOGD_RETF_NONE, "oob.time.sec", NULL },
	{ NULL, NULL, 0, ULOGD_RET_UINT32, ULOGD_RETF_NONE, "oob.time.usec", NULL },
	{ NULL, NULL, 0, ULOGD_RET_UINT32, ULOGD_RETF_NONE, "oob.mark", NULL },
};

ulog_iret_t *_interp_oob(struct ulog_interpreter *ip, ulog_packet_msg_t *pkt)
{
	ulog_iret_t *ret = ip->result;

	ret[0].value.ptr = pkt->prefix;
	ret[0].flags |= ULOGD_RETF_VALID;
	ret[1].value.ui32 = pkt->timestamp_sec;
	ret[1].flags |= ULOGD_RETF_VALID;
	ret[2].value.ui32 = pkt->timestamp_usec;
	ret[2].flags |= ULOGD_RETF_VALID;
	ret[3].value.ui32 = pkt->mark;
	ret[3].flags |= ULOGD_RETF_VALID;
	
	return ret;
}

/***********************************************************************
 * 			IP HEADER
 ***********************************************************************/

static ulog_iret_t iphdr_rets[] = {
	{ NULL, NULL, 0, ULOGD_RET_IPADDR, ULOGD_RETF_NONE, "ip.saddr", 0 },
	{ NULL, NULL, 0, ULOGD_RET_IPADDR, ULOGD_RETF_NONE, "ip.daddr", 0 },
	{ NULL, NULL, 0, ULOGD_RET_UINT8, ULOGD_RETF_NONE, "ip.protocol", 0 },
	{ NULL, NULL, 0, ULOGD_RET_UINT8, ULOGD_RETF_NONE, "ip.tos", 0 },
	{ NULL, NULL, 0, ULOGD_RET_UINT8, ULOGD_RETF_NONE, "ip.ttl", 0 },
	{ NULL, NULL, 0, ULOGD_RET_UINT16, ULOGD_RETF_NONE, "ip.totlen", 0 },
	{ NULL, NULL, 0, ULOGD_RET_UINT8, ULOGD_RETF_NONE, "ip.ihl", 0 },
	{ NULL, NULL, 0, ULOGD_RET_UINT16, ULOGD_RETF_NONE, "ip.csum",  0 },
};

ulog_iret_t *_interp_iphdr(struct ulog_interpreter *ip, ulog_packet_msg_t *pkt)
{
	ulog_iret_t *ret = ip->result;
	struct iphdr *iph = (struct iphdr *) pkt->payload;

	ret[0].value.ui32 = ntohl(iph->saddr);
	ret[0].flags |= ULOGD_RETF_VALID;
	ret[1].value.ui32 = ntohl(iph->daddr);
	ret[1].flags |= ULOGD_RETF_VALID;
	ret[2].value.ui8 = iph->protocol;
	ret[2].flags |= ULOGD_RETF_VALID;
	ret[3].value.ui8 = ntohs(iph->tos);
	ret[3].flags |= ULOGD_RETF_VALID;
	ret[4].value.ui8 = iph->ttl;
	ret[4].flags |= ULOGD_RETF_VALID;
	ret[5].value.ui16 = ntohs(iph->tot_len);
	ret[5].flags |= ULOGD_RETF_VALID;
	ret[6].value.ui8 = iph->ihl;
	ret[6].flags |= ULOGD_RETF_VALID;
	ret[7].value.ui16 = ntohs(iph->check);
	ret[7].flags |= ULOGD_RETF_VALID;

	return ret;
}

/***********************************************************************
 * 			TCP HEADER
 ***********************************************************************/
static ulog_iret_t tcphdr_rets[] = {
	{ NULL, NULL, 0, ULOGD_RET_UINT16, ULOGD_RETF_NONE, "tcp.sport", 0 },
	{ NULL, NULL, 0, ULOGD_RET_UINT16, ULOGD_RETF_NONE, "tcp.dport", 0 },
	{ NULL, NULL, 0, ULOGD_RET_UINT32, ULOGD_RETF_NONE, "tcp.seq", 0 },
	{ NULL, NULL, 0, ULOGD_RET_UINT32, ULOGD_RETF_NONE, "tcp.ackseq", 0 },
	{ NULL, NULL, 0, ULOGD_RET_UINT16, ULOGD_RETF_NONE, "tcp.window", 0 },
	{ NULL, NULL, 0, ULOGD_RET_BOOL, ULOGD_RETF_NONE, "tcp.urg", 0 },
	{ NULL, NULL, 0, ULOGD_RET_UINT16, ULOGD_RETF_NONE, "tcp.urgp", 0 },
	{ NULL, NULL, 0, ULOGD_RET_BOOL, ULOGD_RETF_NONE, "tcp.ack", 0 },
	{ NULL, NULL, 0, ULOGD_RET_BOOL, ULOGD_RETF_NONE, "tcp.psh", 0 },
	{ NULL, NULL, 0, ULOGD_RET_BOOL, ULOGD_RETF_NONE, "tcp.rst", 0 },
	{ NULL, NULL, 0, ULOGD_RET_BOOL, ULOGD_RETF_NONE, "tcp.syn", 0 },
	{ NULL, NULL, 0, ULOGD_RET_BOOL, ULOGD_RETF_NONE, "tcp.fin", 0 },
};

ulog_iret_t *_interp_tcphdr(struct ulog_interpreter *ip, ulog_packet_msg_t *pkt)
{
	struct iphdr *iph = (struct iphdr *) pkt->payload;
	void *protoh = (u_int32_t *)iph + iph->ihl;
	struct tcphdr *tcph = (struct tcphdr *) protoh;
	ulog_iret_t *ret = ip->result;

	if (iph->protocol != IPPROTO_TCP)
		return NULL;
	
	ret[0].value.ui16 = ntohs(tcph->source);
	ret[0].flags |= ULOGD_RETF_VALID;
	ret[1].value.ui16 = ntohs(tcph->dest);
	ret[1].flags |= ULOGD_RETF_VALID;
	ret[2].value.ui32 = ntohl(tcph->seq);
	ret[2].flags |= ULOGD_RETF_VALID;
	ret[3].value.ui32 = ntohl(tcph->ack_seq);
	ret[3].flags |= ULOGD_RETF_VALID;
	ret[4].value.ui16 = ntohs(tcph->window);
	ret[4].flags |= ULOGD_RETF_VALID;
	if (tcph->urg) {
		ret[5].value.b = tcph->urg;
		ret[5].flags |= ULOGD_RETF_VALID;
		ret[6].value.ui16 = ntohs(tcph->urg_ptr);
		ret[6].flags |= ULOGD_RETF_VALID;
	}
	if (tcph->ack) {
		ret[7].value.b = tcph->ack;
		ret[7].flags |= ULOGD_RETF_VALID;
	}
	if (tcph->psh) {
		ret[8].value.b = tcph->psh;
		ret[8].flags |= ULOGD_RETF_VALID;
	}
	if (tcph->rst) {
		ret[9].value.b = tcph->rst;
		ret[9].flags |= ULOGD_RETF_VALID;
	}
	if (tcph->syn) {
		ret[10].value.b = tcph->syn;
		ret[10].flags |= ULOGD_RETF_VALID;
	}
	if (tcph->fin) {
		ret[11].value.b = tcph->fin;
		ret[11].flags |= ULOGD_RETF_VALID;
	}
	
	return ret;
}

/***********************************************************************
 * 			UDP HEADER
 ***********************************************************************/
static ulog_iret_t udphdr_rets[] = {
	{ NULL, NULL, 0, ULOGD_RET_UINT16, ULOGD_RETF_NONE, "udp.sport", 0 },
	{ NULL, NULL, 0, ULOGD_RET_UINT16, ULOGD_RETF_NONE, "udp.dport", 0 },
	{ NULL, NULL, 0, ULOGD_RET_UINT16, ULOGD_RETF_NONE, "upd.len", 0 },
};
ulog_iret_t *_interp_udp(struct ulog_interpreter *ip, ulog_packet_msg_t *pkt)
{
	struct iphdr *iph = (struct iphdr *) pkt->payload;
	void *protoh = (u_int32_t *)iph + iph->ihl;
	struct udphdr *udph = protoh;
	ulog_iret_t *ret = ip->result;

	if (iph->protocol != IPPROTO_UDP)
		return NULL;

	ret[0].value.ui16 = ntohs(udph->source);
	ret[0].flags |= ULOGD_RETF_VALID;
	ret[1].value.ui16 = ntohs(udph->dest);
	ret[1].flags |= ULOGD_RETF_VALID;
	ret[2].value.ui16 = ntohs(udph->len);
	ret[2].flags |= ULOGD_RETF_VALID;
	
	return ret;
}

/***********************************************************************
 * 			ICMP HEADER
 ***********************************************************************/

static ulog_iret_t icmphdr_rets[] = {
	{ NULL, NULL, 0, ULOGD_RET_UINT16, ULOGD_RETF_NONE, "icmp.type", 0 },
};

ulog_iret_t *_interp_icmp(struct ulog_interpreter *ip, ulog_packet_msg_t *pkt)
{
	struct iphdr *iph = (struct iphdr *) pkt->payload;
	void *protoh = (u_int32_t *) (iph + iph->ihl);
	struct icmphdr *icmph = protoh;
	ulog_iret_t *ret = ip->result;

	if (iph->protocol != IPPROTO_ICMP)
		return NULL;
	
	ret[0].value.ui8 = icmph->type;
	ret[0].flags |= ULOGD_RETF_VALID;

	return ret;

}

static ulog_interpreter_t base_ip[] = {
	{ NULL, "raw", 0, &_interp_mac, 1, &mac_rets },
	{ NULL, "oob", 0, &_interp_oob, 4, &oob_rets },
	{ NULL, "ip", 0, &_interp_iphdr, 8, &iphdr_rets },
	{ NULL, "tcp", 0, &_interp_tcphdr, 12, &tcphdr_rets },
	{ NULL, "icmp", 0, &_interp_icmp, 1, &icmphdr_rets },
	{ NULL, "udp", 0, &_interp_udp, 3, &udphdr_rets },
	{ NULL, "", 0, NULL, 0, { NULL } }, 
};

void _base_reg_ip(void)
{
	ulog_interpreter_t *ip = base_ip;
	ulog_interpreter_t *p;

	for (p = ip; p->interp; p++) {
		register_interpreter(p);
	}

}

void _init(void)
{
	_base_reg_ip();
}
