/* ulogd_MAC.c, Version $Revision: 1.12 $
 *
 * ulogd interpreter plugin for 
 * 	o MAC addresses
 * 	o NFMARK field
 * 	o TIME
 * 	o Interface names
 * 	o IP header
 * 	o TCP header
 * 	o UDP header
 * 	o ICMP header
 * 	o AH/ESP header
 *
 * (C) 2000-2001 by Harald Welte <laforge@gnumonks.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 
 *  as published by the Free Software Foundation
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 
 * $Id: ulogd_BASE.c,v 1.12 2002/06/13 12:55:21 laforge Exp $
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
static ulog_iret_t raw_rets[] = {
	{ NULL, NULL, 0, ULOGD_RET_STRING, ULOGD_RETF_FREE, "raw.mac", 
	  { ptr: NULL } },
	{ NULL, NULL, 0, ULOGD_RET_RAW, ULOGD_RETF_NONE, "raw.pkt",
	  { ptr: NULL } },
	{ NULL, NULL, 0, ULOGD_RET_UINT32, ULOGD_RETF_NONE, "raw.pktlen",
	  { ui32: 0 } },
};

static ulog_iret_t *_interp_raw(struct ulog_interpreter *ip, 
				ulog_packet_msg_t *pkt)
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

	return ret;
}

/***********************************************************************
 * 			OUT OF BAND
 ***********************************************************************/

static ulog_iret_t oob_rets[] = {
	{ NULL, NULL, 0, ULOGD_RET_STRING, ULOGD_RETF_NONE, "oob.prefix", 
		{ ptr: NULL } },
	{ NULL, NULL, 0, ULOGD_RET_UINT32, ULOGD_RETF_NONE, "oob.time.sec", 
		{ ui32: 0 } },
	{ NULL, NULL, 0, ULOGD_RET_UINT32, ULOGD_RETF_NONE, "oob.time.usec", 
		{ ui32: 0 } },
	{ NULL, NULL, 0, ULOGD_RET_UINT32, ULOGD_RETF_NONE, "oob.mark", 
		{ ui32: 0 } },
	{ NULL, NULL, 0, ULOGD_RET_STRING, ULOGD_RETF_NONE, "oob.in", 
		{ ptr: NULL } },
	{ NULL, NULL, 0, ULOGD_RET_STRING, ULOGD_RETF_NONE, "oob.out", 
		{ ptr: NULL } },
};

static ulog_iret_t *_interp_oob(struct ulog_interpreter *ip, 
				ulog_packet_msg_t *pkt)
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
	ret[4].value.ptr = pkt->indev_name;
	ret[4].flags |= ULOGD_RETF_VALID;
	ret[5].value.ptr = pkt->outdev_name;
	ret[5].flags |= ULOGD_RETF_VALID;
	
	return ret;
}

/***********************************************************************
 * 			IP HEADER
 ***********************************************************************/

static ulog_iret_t iphdr_rets[] = {
	{ NULL, NULL, 0, ULOGD_RET_IPADDR, ULOGD_RETF_NONE, "ip.saddr", 
		{ ui32: 0 } },
	{ NULL, NULL, 0, ULOGD_RET_IPADDR, ULOGD_RETF_NONE, "ip.daddr", 
		{ ui32: 0 } },
	{ NULL, NULL, 0, ULOGD_RET_UINT8, ULOGD_RETF_NONE, "ip.protocol", 
		{ ui8: 0 } },
	{ NULL, NULL, 0, ULOGD_RET_UINT8, ULOGD_RETF_NONE, "ip.tos", 
		{ ui8: 0 } },
	{ NULL, NULL, 0, ULOGD_RET_UINT8, ULOGD_RETF_NONE, "ip.ttl", 
		{ ui8: 0 } },
	{ NULL, NULL, 0, ULOGD_RET_UINT16, ULOGD_RETF_NONE, "ip.totlen", 
		{ ui16: 0 } },
	{ NULL, NULL, 0, ULOGD_RET_UINT8, ULOGD_RETF_NONE, "ip.ihl", 
		{ ui8: 0 } },
	{ NULL, NULL, 0, ULOGD_RET_UINT16, ULOGD_RETF_NONE, "ip.csum", 
		{ ui16: 0 } },
	{ NULL, NULL, 0, ULOGD_RET_UINT16, ULOGD_RETF_NONE, "ip.id", 
		{ ui16: 0 } },
	{ NULL, NULL, 0, ULOGD_RET_UINT16, ULOGD_RETF_NONE, "ip.fragoff", 
		{ ui16: 0 } },
};

static ulog_iret_t *_interp_iphdr(struct ulog_interpreter *ip, 
				ulog_packet_msg_t *pkt)
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
	ret[8].value.ui16 = ntohs(iph->id);
	ret[8].flags |= ULOGD_RETF_VALID;
	ret[9].value.ui16 = ntohs(iph->frag_off);
	ret[9].flags |= ULOGD_RETF_VALID;

	return ret;
}

/***********************************************************************
 * 			TCP HEADER
 ***********************************************************************/
static ulog_iret_t tcphdr_rets[] = {
	{ NULL, NULL, 0, ULOGD_RET_UINT16, ULOGD_RETF_NONE, "tcp.sport", 
		{ ui16: 0 } },
	{ NULL, NULL, 0, ULOGD_RET_UINT16, ULOGD_RETF_NONE, "tcp.dport", 
		{ ui16: 0 } },
	{ NULL, NULL, 0, ULOGD_RET_UINT32, ULOGD_RETF_NONE, "tcp.seq", 
		{ ui32: 0 } },
	{ NULL, NULL, 0, ULOGD_RET_UINT32, ULOGD_RETF_NONE, "tcp.ackseq", 
		{ ui32: 0 } },
	{ NULL, NULL, 0, ULOGD_RET_UINT16, ULOGD_RETF_NONE, "tcp.window",
		{ ui16:	0 } },
	{ NULL, NULL, 0, ULOGD_RET_BOOL, ULOGD_RETF_NONE, "tcp.urg", 
		{ b: 0 } },
	{ NULL, NULL, 0, ULOGD_RET_UINT16, ULOGD_RETF_NONE, "tcp.urgp",
		{ ui16: 0 } },
	{ NULL, NULL, 0, ULOGD_RET_BOOL, ULOGD_RETF_NONE, "tcp.ack", 
		{ b: 0 } },
	{ NULL, NULL, 0, ULOGD_RET_BOOL, ULOGD_RETF_NONE, "tcp.psh", 
		{ b: 0 } },
	{ NULL, NULL, 0, ULOGD_RET_BOOL, ULOGD_RETF_NONE, "tcp.rst", 
		{ b: 0 } },
	{ NULL, NULL, 0, ULOGD_RET_BOOL, ULOGD_RETF_NONE, "tcp.syn", 
		{ b: 0 } },
	{ NULL, NULL, 0, ULOGD_RET_BOOL, ULOGD_RETF_NONE, "tcp.fin", 
		{ b: 0 } },
};

static ulog_iret_t *_interp_tcphdr(struct ulog_interpreter *ip, 
				ulog_packet_msg_t *pkt)
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
	{ NULL, NULL, 0, ULOGD_RET_UINT16, ULOGD_RETF_NONE, "udp.sport", 
		{ ui16 :0 } },
	{ NULL, NULL, 0, ULOGD_RET_UINT16, ULOGD_RETF_NONE, "udp.dport", 
		{ ui16: 0 } },
	{ NULL, NULL, 0, ULOGD_RET_UINT16, ULOGD_RETF_NONE, "udp.len", 
		{ ui16: 0 } },
};

static ulog_iret_t *_interp_udp(struct ulog_interpreter *ip, 
				ulog_packet_msg_t *pkt)
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
	{ NULL, NULL, 0, ULOGD_RET_UINT8, ULOGD_RETF_NONE, "icmp.type", 
		{ ui8: 0 } },
	{ NULL, NULL, 0, ULOGD_RET_UINT8, ULOGD_RETF_NONE, "icmp.code", 
		{ ui8: 0 } },
	{ NULL, NULL, 0, ULOGD_RET_UINT16, ULOGD_RETF_NONE, "icmp.echoid", 
		{ ui16: 0 } },
	{ NULL, NULL, 0, ULOGD_RET_UINT16, ULOGD_RETF_NONE, "icmp.echoseq", 
		{ ui16: 0 } },
	{ NULL, NULL, 0, ULOGD_RET_IPADDR, ULOGD_RETF_NONE, "icmp.gateway", 
		{ ui32: 0 } },
	{ NULL, NULL, 0, ULOGD_RET_UINT16, ULOGD_RETF_NONE, "icmp.fragmtu", 
		{ ui16: 0 } },
};

static ulog_iret_t *_interp_icmp(struct ulog_interpreter *ip, 
				ulog_packet_msg_t *pkt)
{
	struct iphdr *iph = (struct iphdr *) pkt->payload;
	void *protoh = (u_int32_t *)iph + iph->ihl;
	struct icmphdr *icmph = protoh;
	ulog_iret_t *ret = ip->result;

	if (iph->protocol != IPPROTO_ICMP)
		return NULL;
	
	ret[0].value.ui8 = icmph->type;
	ret[0].flags |= ULOGD_RETF_VALID;
	ret[1].value.ui8 = icmph->code;
	ret[1].flags |= ULOGD_RETF_VALID;

	switch(icmph->type) {
		case ICMP_ECHO:
		case ICMP_ECHOREPLY:
			ret[2].value.ui16 = ntohs(icmph->un.echo.id);
			ret[2].flags |= ULOGD_RETF_VALID;
			ret[3].value.ui16 = ntohs(icmph->un.echo.sequence);
			ret[3].flags |= ULOGD_RETF_VALID;
			break;
		case ICMP_REDIRECT:
		case ICMP_PARAMETERPROB:
			ret[4].value.ui32 = ntohl(icmph->un.gateway);
			ret[4].flags |= ULOGD_RETF_VALID;
			break;
		case ICMP_DEST_UNREACH:
			if (icmph->code == ICMP_FRAG_NEEDED) {
				ret[5].value.ui16 = ntohs(icmph->un.frag.mtu);
				ret[5].flags |= ULOGD_RETF_VALID;
			}
			break;
	}
	return ret;
}

/***********************************************************************
 * 			IPSEC HEADER 
 ***********************************************************************/

static ulog_iret_t ahesphdr_rets[] = {
	{ NULL, NULL, 0, ULOGD_RET_UINT8, ULOGD_RETF_NONE, "ahesp.spi", 
		{ ui8: 0 } },
};

static ulog_iret_t *_interp_ahesp(struct ulog_interpreter *ip, 
				ulog_packet_msg_t *pkt)
{

	ulog_iret_t *ret = ip->result;
#if 0
	struct iphdr *iph = (struct iphdr *) pkt->payload;
	void *protoh = (u_int32_t *) (iph + iph->ihl);
	struct esphdr *esph = protoh;

	if (iph->protocol != IPPROTO_ESP)
		return NULL;

	ret[0].value.ui32 = ntohl(esph->spi);
	ret[0].flags |= ULOGD_RETF_VALID;
#endif

	return ret;
}


static ulog_interpreter_t base_ip[] = {
	{ NULL, "raw", 0, &_interp_raw, 3, &raw_rets },
	{ NULL, "oob", 0, &_interp_oob, 6, &oob_rets },
	{ NULL, "ip", 0, &_interp_iphdr, 10, &iphdr_rets },
	{ NULL, "tcp", 0, &_interp_tcphdr, 12, &tcphdr_rets },
	{ NULL, "icmp", 0, &_interp_icmp, 6, &icmphdr_rets },
	{ NULL, "udp", 0, &_interp_udp, 3, &udphdr_rets },
	{ NULL, "ahesp", 0, &_interp_ahesp, 1, &ahesphdr_rets },
	{ NULL, "", 0, NULL, 0, NULL }, 
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
