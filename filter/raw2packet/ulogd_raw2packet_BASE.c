/* ulogd_MAC.c, Version $Revision$
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
 * (C) 2000-2005 by Harald Welte <laforge@gnumonks.org>
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
 
 * $Id$
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <ulogd/ulogd.h>


/***********************************************************************
 * 			IP HEADER
 ***********************************************************************/

static struct ulogd_key iphdr_rets[] = {
	{ 
		.type = ULOGD_RET_IPADDR,
		.flags = ULOGD_RETF_NONE, 
		.name = "ip.saddr", 
		.ipfix = { .vendor = 0, .field_id = 8 },
	},
	{
		.type = ULOGD_RET_IPADDR,
		.flags = ULOGD_RETF_NONE,
		.name = "ip.daddr", 
		.ipfix = { .vendor = 0, .field_id = 12 },
	},
	{
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "ip.protocol", 
		.ipfix = { .vendor = 0, .field_id = 4 },
	},
	{
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "ip.tos", 
		.ipfix = { .vendor = 0, .field_id = 5 },
	},
	{
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "ip.ttl", 
	},
	{
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "ip.totlen", 
	},
	{
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "ip.ihl", 
	},
	{
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "ip.csum", 
	},
	{
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name "ip.id", 
	},
	{
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "ip.fragoff", 
	},
};

static struct ulog_key *_interp_iphdr(struct ulogd_pluginstance *pi)
{
	struct ulogd_key *ret = pi->output;
	struct iphdr *iph = (struct iphdr *) pi->input[0].u.value.ptr;

	ret[0].u.value.ui32 = ntohl(iph->saddr);
	ret[0].flags |= ULOGD_RETF_VALID;
	ret[1].u.value.ui32 = ntohl(iph->daddr);
	ret[1].flags |= ULOGD_RETF_VALID;
	ret[2].u.value.ui8 = iph->protocol;
	ret[2].flags |= ULOGD_RETF_VALID;
	ret[3].u.value.ui8 = iph->tos;
	ret[3].flags |= ULOGD_RETF_VALID;
	ret[4].u.value.ui8 = iph->ttl;
	ret[4].flags |= ULOGD_RETF_VALID;
	ret[5].u.value.ui16 = ntohs(iph->tot_len);
	ret[5].flags |= ULOGD_RETF_VALID;
	ret[6].u.value.ui8 = iph->ihl;
	ret[6].flags |= ULOGD_RETF_VALID;
	ret[7].u.value.ui16 = ntohs(iph->check);
	ret[7].flags |= ULOGD_RETF_VALID;
	ret[8].u.value.ui16 = ntohs(iph->id);
	ret[8].flags |= ULOGD_RETF_VALID;
	ret[9].u.value.ui16 = ntohs(iph->frag_off);
	ret[9].flags |= ULOGD_RETF_VALID;

	return 0;
}

#if 0
/***********************************************************************
 * 			TCP HEADER
 ***********************************************************************/
static ulog_iret_t tcphdr_rets[] = {
	{
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.sport", 
		.ipfix = { .vendor = 0, .field_id = 7 },
	},
	{
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.dport", 
		.ipfix = { .vendor = 0, .field_id = 11 },
	},
	{
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.seq", 
	},
	{
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.ackseq", 
	}
	{
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE, 
		.name = "tcp.offset",
	},
	{
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.reserved",
	}, 
	{
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.window",
	},
	{
		.type = ULOGD_RET_BOOL, 
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.urg", 
	},
	{
		.type = ULOGD_RET_UINT16, 
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.urgp",
	},
	{
		.type = ULOGD_RET_BOOL, 
		.flags = ULOGD_RETF_NONE, 
		.name = "tcp.ack", 
	},
	{ NULL, NULL, 0, ULOGD_RET_BOOL, ULOGD_RETF_NONE, "tcp.psh", 
		{ b: 0 } },
	{ NULL, NULL, 0, ULOGD_RET_BOOL, ULOGD_RETF_NONE, "tcp.rst", 
		{ b: 0 } },
	{ NULL, NULL, 0, ULOGD_RET_BOOL, ULOGD_RETF_NONE, "tcp.syn", 
		{ b: 0 } },
	{ NULL, NULL, 0, ULOGD_RET_BOOL, ULOGD_RETF_NONE, "tcp.fin", 
		{ b: 0 } },
	{ NULL, NULL, 0, ULOGD_RET_BOOL, ULOGD_RETF_NONE, "tcp.res1",
		{ b: 0 } },
	{ NULL, NULL, 0, ULOGD_RET_BOOL, ULOGD_RETF_NONE, "tcp.res2",
		{ b: 0 } },
	{ NULL, NULL, 0, ULOGD_RET_UINT16, ULOGD_RETF_NONE, "tcp.csum",
		{ ui16: 0 } },
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
	
	ret[0].u.value.ui16 = ntohs(tcph->source);
	ret[0].flags |= ULOGD_RETF_VALID;
	ret[1].u.value.ui16 = ntohs(tcph->dest);
	ret[1].flags |= ULOGD_RETF_VALID;
	ret[2].u.value.ui32 = ntohl(tcph->seq);
	ret[2].flags |= ULOGD_RETF_VALID;
	ret[3].u.value.ui32 = ntohl(tcph->ack_seq);
	ret[3].flags |= ULOGD_RETF_VALID;
	ret[4].u.value.ui8 = ntohs(tcph->doff);
	ret[4].flags |= ULOGD_RETF_VALID;
	ret[5].u.value.ui8 = ntohs(tcph->res1);
	ret[5].flags |= ULOGD_RETF_VALID;
	ret[6].u.value.ui16 = ntohs(tcph->window);
	ret[6].flags |= ULOGD_RETF_VALID;

	ret[7].u.value.b = tcph->urg;
	ret[7].flags |= ULOGD_RETF_VALID;
	if (tcph->urg) {
		ret[8].u.value.ui16 = ntohs(tcph->urg_ptr);
		ret[8].flags |= ULOGD_RETF_VALID;
	}
	ret[9].u.value.b = tcph->ack;
	ret[9].flags |= ULOGD_RETF_VALID;
	ret[10].u.value.b = tcph->psh;
	ret[10].flags |= ULOGD_RETF_VALID;
	ret[11].u.value.b = tcph->rst;
	ret[11].flags |= ULOGD_RETF_VALID;
	ret[12].u.value.b = tcph->syn;
	ret[12].flags |= ULOGD_RETF_VALID;
	ret[13].u.value.b = tcph->fin;
	ret[13].flags |= ULOGD_RETF_VALID;
	ret[14].u.value.b = tcph->res1;
	ret[14].flags |= ULOGD_RETF_VALID;
	ret[15].u.value.b = tcph->res2;
	ret[15].flags |= ULOGD_RETF_VALID;
	ret[16].u.value.ui16 = ntohs(tcph->check);
	ret[16].u.value.ui16 = ULOGD_RETF_VALID;
	
	return ret;
}

/***********************************************************************
 * 			UDP HEADER
 ***********************************************************************/
static ulog_iret_t udphdr_rets[] = {
	{
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "udp.sport", 
		.ipfix = { .vendor = 0, .field_id = 7 },
	},
	{
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "udp.dport", 
		.ipfix = { .vendor = 0, .field_id = 11 },
	},
	{
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "udp.len", 
	},
	{
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "udp.csum",
	},
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

	ret[0].u.value.ui16 = ntohs(udph->source);
	ret[0].flags |= ULOGD_RETF_VALID;
	ret[1].u.value.ui16 = ntohs(udph->dest);
	ret[1].flags |= ULOGD_RETF_VALID;
	ret[2].u.value.ui16 = ntohs(udph->len);
	ret[2].flags |= ULOGD_RETF_VALID;
	ret[3].u.value.ui16 = ntohs(udph->check);
	ret[3].flags |= ULOGD_RETF_VALID;
	
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
	{ NULL, NULL, 0, ULOGD_RET_UINT16, ULOGD_RETF_NONE, "icmp.csum",
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
	
	ret[0].u.value.ui8 = icmph->type;
	ret[0].flags |= ULOGD_RETF_VALID;
	ret[1].u.value.ui8 = icmph->code;
	ret[1].flags |= ULOGD_RETF_VALID;

	switch(icmph->type) {
		case ICMP_ECHO:
		case ICMP_ECHOREPLY:
			ret[2].u.value.ui16 = ntohs(icmph->un.echo.id);
			ret[2].flags |= ULOGD_RETF_VALID;
			ret[3].u.value.ui16 = ntohs(icmph->un.echo.sequence);
			ret[3].flags |= ULOGD_RETF_VALID;
			break;
		case ICMP_REDIRECT:
		case ICMP_PARAMETERPROB:
			ret[4].u.value.ui32 = ntohl(icmph->un.gateway);
			ret[4].flags |= ULOGD_RETF_VALID;
			break;
		case ICMP_DEST_UNREACH:
			if (icmph->code == ICMP_FRAG_NEEDED) {
				ret[5].u.value.ui16 = ntohs(icmph->un.frag.mtu);
				ret[5].flags |= ULOGD_RETF_VALID;
			}
			break;
	}
	ret[6].u.value.ui16 = icmph->checksum;
	ret[6].flags |= ULOGD_RETF_VALID;

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

	ret[0].u.value.ui32 = ntohl(esph->spi);
	ret[0].flags |= ULOGD_RETF_VALID;
#endif

	return ret;
}


static ulog_interpreter_t base_ip[] = {
	{ NULL, "ip", 0, &_interp_iphdr, 10, iphdr_rets },
	{ NULL, "tcp", 0, &_interp_tcphdr, 17, tcphdr_rets },
	{ NULL, "icmp", 0, &_interp_icmp, 7, icmphdr_rets },
	{ NULL, "udp", 0, &_interp_udp, 4, udphdr_rets },
	{ NULL, "ahesp", 0, &_interp_ahesp, 1, ahesphdr_rets },
	{ NULL, "", 0, NULL, 0, NULL }, 
};
#endif

static struct ulogd_key base_inp[] = {
	{ 
		.type = ULOGD_RET_RAW,
		.name = "raw.pkt", 
		.ipfix = { 
			.vendor = IPFIX_VENDOR_NETFILTER, 
			.field_id = 1 
		},
	},
};

static struct ulogd_pluginstance *base_init(struct ulogd_plugin *pl)
{
	struct ulogd_pluginstance *bpi = malloc(sizeof(*bpi));

	if (!bpi)
		return NULL;

	bpi->plugin = pl;
	//bpi->input = &base_inp;
	//bpi->output = &iphdr_rets;

	return bpi;
}

static int base_fini(struct ulogd_pluginstance *upi)
{
	free(upi);
	return 0;
}

static struct ulogd_plugin base_plugin = {
	.name = "BASE",
	.input = {
		.keys = &base_inp,
		.num_keys = 1,
		.type = ULOGD_DTYPE_RAW,
		},
	.output = {
		.keys = &iphdr_rets,
//		.num_keys = 39,
		.num_keys = 10,
		.type = ULOGD_DTYPE_PACKET,
		},
//	.interp = &base_interp,
	.interp = &_interp_iphdr,

	.constructor = &base_init,
	.destructor = &base_fini,
};

void _init(void)
{
	ulogd_register_plugin(&base_plugin);
}
