/* ulogd_MAC.c, Version $Revision$
 *
 * ulogd logging interpreter for MAC addresses, TIME, etc.
 *
 * (C) 2000 by Harald Welte <laforge@sunbeam.franken.de>
 * This software is released under the terms of GNU GPL
 *
 * $Id$
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <ulogd.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/icmp.h>

#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[3]


ulog_iret_t *_interp_mac(ulog_packet_msg_t *pkt)
{
	unsigned char *p;
	int i;
	char *buf;
	ulog_iret_t *ret;
	
	if (pkt->mac_len)
	{
		buf = (char *) malloc(3 * pkt->mac_len + 1);
		*buf = 0;

		p = pkt->mac;
		for (i = 0; i < pkt->mac_len; i++, p++)
			sprintf(buf, "%s%02x%c", buf, *p, i==pkt->mac_len-1 ? ' ':':');
		ret = alloc_ret(ULOGD_RET_STRING,"raw.mac.addr");
		ret->value = buf;
		return ret;

	}
	return NULL;
}

ulog_iret_t *_interp_time(ulog_packet_msg_t *pkt)
{
	ulog_iret_t *ret, *ret2;
	unsigned long *ptr;
	
	ret = alloc_ret(ULOGD_RET_UINT64, "oob.time.sec");
	ret2 = alloc_ret(ULOGD_RET_UINT64, "oob.time.usec");

	ptr = (unsigned long *) malloc(sizeof(unsigned long));
	*ptr = pkt->timestamp_sec;
	ret->value = ptr;
	ret->next = ret2;

	ptr = (unsigned long *) malloc (sizeof(unsigned long));
	*ptr = pkt->timestamp_usec;
	ret2->value = ptr;
	
	return ret;
}

ulog_iret_t *_interp_prefix(ulog_packet_msg_t *pkt)
{
	ulog_iret_t *ret;
	
	ret = alloc_ret(ULOGD_RET_STRING, "oob.prefix");
	ret->value = malloc(sizeof(pkt->prefix));
	strcpy(ret->value, pkt->prefix);
	
	return ret;
}

ulog_iret_t *_interp_mark(ulog_packet_msg_t *pkt)
{
	ulog_iret_t *ret;
	u_int32_t *mk;

	ret = alloc_ret(ULOGD_RET_UINT32, "oob.mark");
	mk = (u_int32_t *) malloc(sizeof(u_int32_t));
	*mk = pkt->mark;
	ret->value = mk;

	return ret;	
}

ulog_iret_t *_interp_iphdr(ulog_packet_msg_t *pkt)
{
	ulog_iret_t *ret, *ret2;
	struct iphdr *iph = (struct iphdr *) pkt->payload;
	u_int32_t *ip;
	u_int8_t *ui8;
	u_int16_t *ui16;

	ret = alloc_ret(ULOGD_RET_IPADDR, "ip.hdr.saddr");
	ip = malloc(sizeof(u_int32_t));
	*ip = iph->saddr;
	ret->value = ip;

	ret->next = ret2 = alloc_ret(ULOGD_RET_IPADDR, "ip.hdr.daddr");
	ip = malloc(sizeof(u_int32_t));
	*ip = iph->daddr;
	ret2->value = ip;

	ret2 = ret2->next = alloc_ret(ULOGD_RET_UINT8, "ip.hdr.protocol");
	ui8 = malloc(sizeof(u_int8_t));
	*ui8 = iph->protocol;
	ret2->value = ui8;

	ret2 = ret2->next = alloc_ret(ULOGD_RET_UINT8, "ip.hdr.tos");
	ui8 = malloc(sizeof(u_int8_t));
	*ui8 = ntohs(iph->tos);
	ret2->value = ui8;

	ret2 = ret2->next = alloc_ret(ULOGD_RET_UINT8, "ip.hdr.ttl");
	ui8 = malloc(sizeof(u_int8_t));
	*ui8 = iph->ttl;
	ret2->value = ui8;

	ret2 = ret2->next = alloc_ret(ULOGD_RET_UINT16, "ip.hdr.tot_len");
	ui16 = malloc(sizeof(u_int16_t));
	*ui16 = ntohs(iph->tot_len);
	ret2->value = ui16;

	ret2 = ret2->next = alloc_ret(ULOGD_RET_UINT8, "ip.hdr.ihl");
	ui8 = malloc(sizeof(u_int8_t));
	*ui8 = iph->ihl;
	ret2->value = ui8;

	return ret;
}

ulog_iret_t *_interp_tcphdr(ulog_packet_msg_t *pkt)
{
	struct iphdr *iph = (struct iphdr *) pkt->payload;
	struct tcphdr *tcph = (struct tcphdr *) (iph + iph->ihl);
	ulog_iret_t *ret, *ret2;
	u_int16_t *ui16;
	u_int32_t *ui32;

	if (iph->protocol != IPPROTO_TCP)
		return NULL;
	
	ret = alloc_ret(ULOGD_RET_UINT16, "tcp.hdr.sport");
	ui16 = malloc(sizeof(u_int16_t));
	*ui16 = ntohs(tcph->source);
	ret->value = ui16;

	ret->next = ret2 = alloc_ret(ULOGD_RET_UINT16, "tcp.hdr.sport");
	ui16 = malloc(sizeof(u_int16_t));
	*ui16 = ntohs(tcph->dest);
	ret2->value = ui16;

	ret2 = ret2->next = alloc_ret(ULOGD_RET_UINT32, "tcp.hdr.seq");
	ui32 = malloc(sizeof(u_int32_t));
	*ui32 = ntohl(tcph->seq);
	ret2->value = ui32;

	ret2 = ret2->next = alloc_ret(ULOGD_RET_UINT32, "tcp.hdr.ack_seq");
	ui32 = malloc(sizeof(u_int32_t));
	*ui32 = ntohl(tcph->ack_seq);
	ret2->value = ui32;
	
	
	return ret;
}

ulog_iret_t *_interp_icmp(ulog_packet_msg_t *pkt)
{
	struct iphdr *iph = (struct iphdr *) pkt->payload;
	struct icmphdr *icmph = (struct icmphdr *) (iph + iph->ihl);
	ulog_iret_t *ret, *ret2;
	u_int8_t *ui8;

	if (iph->protocol != IPPROTO_ICMP)
		return NULL;
	
	ret = alloc_ret(ULOGD_RET_UINT8, "icmp.hdr.type");
	ui8 = malloc(sizeof(u_int8_t));
	*ui8 = icmph->type;
	ret->value = ui8;

	return ret;

}

static ulog_interpreter_t base_ip[] = { 

	{ NULL, "raw.mac", &_interp_mac },
	{ NULL, "oob.time", &_interp_time },
	{ NULL, "oob.prefix", &_interp_prefix },
	{ NULL, "oob.mark", &_interp_mark },
	{ NULL, "ip.hdr", &_interp_iphdr },
	{ NULL, "tcp.hdr", &_interp_tcphdr },
	{ NULL, "icmp.hdr", &_interp_icmp },
	{ NULL, "", NULL }, 
};

void _init(void)
{
	ulog_interpreter_t *ip = base_ip;
	ulog_interpreter_t *p;

	for (p = ip; p->interp; p++)
	{
		register_interpreter(p);
	}

}
