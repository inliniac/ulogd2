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
#include <netinet/ip6.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/udp.h>
#include <ulogd/ulogd.h>
#include <ulogd/ipfix_protocol.h>

enum output_keys {
	KEY_IP_SADDR,
	KEY_IP_DADDR,
	KEY_IP_PROTOCOL,
	KEY_IP_TOS,
	KEY_IP_TTL,
	KEY_IP_TOTLEN,
	KEY_IP_IHL,
	KEY_IP_CSUM,
	KEY_IP_ID,
	KEY_IP_FRAGOFF,
	KEY_IP6_SADDR,
	KEY_IP6_DADDR,
	KEY_IP6_PAYLOAD_LEN,
	KEY_IP6_PRIORITY,
	KEY_IP6_FLOWLABEL,
	KEY_IP6_HOPLIMIT,
	KEY_IP6_NEXTHDR,
	KEY_IP6_FRAG_OFF,
	KEY_IP6_FRAG_ID,
	KEY_TCP_SPORT,
	KEY_TCP_DPORT,
	KEY_TCP_SEQ,
	KEY_TCP_ACKSEQ,
	KEY_TCP_WINDOW,
	KEY_TCP_OFFSET,
	KEY_TCP_RESERVED,
	KEY_TCP_URG,
	KEY_TCP_URGP,
	KEY_TCP_ACK,
	KEY_TCP_PSH,
	KEY_TCP_RST,
	KEY_TCP_SYN,
	KEY_TCP_FIN,
	KEY_TCP_RES1,
	KEY_TCP_RES2,
	KEY_TCP_CSUM,
	KEY_UDP_SPORT,
	KEY_UDP_DPORT,
	KEY_UDP_LEN,
	KEY_UDP_CSUM,
	KEY_ICMP_TYPE,
	KEY_ICMP_CODE,
	KEY_ICMP_ECHOID,
	KEY_ICMP_ECHOSEQ,
	KEY_ICMP_GATEWAY,
	KEY_ICMP_FRAGMTU,
	KEY_ICMP_CSUM,
	KEY_ICMPV6_TYPE,
	KEY_ICMPV6_CODE,
	KEY_ICMPV6_ECHOID,
	KEY_ICMPV6_ECHOSEQ,
	KEY_ICMPV6_CSUM,
	KEY_AHESP_SPI,
};

static struct ulogd_key iphdr_rets[] = {
	[KEY_IP_SADDR] = { 
		.type = ULOGD_RET_IPADDR,
		.flags = ULOGD_RETF_NONE, 
		.name = "ip.saddr", 
		.ipfix = { 
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_sourceIPv4Address,
		},
	},
	[KEY_IP_DADDR] = {
		.type = ULOGD_RET_IPADDR,
		.flags = ULOGD_RETF_NONE,
		.name = "ip.daddr", 
		.ipfix = { 
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_destinationIPv4Address,
		},
	},
	[KEY_IP_PROTOCOL] = {
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "ip.protocol", 
		.ipfix = { 
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_protocolIdentifier,
		},
	},
	[KEY_IP_TOS] = {
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "ip.tos", 
		.ipfix = { 
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_classOfServiceIPv4,
		},
	},
	[KEY_IP_TTL] = {
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "ip.ttl", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_ipTimeToLive,
		},
	},
	[KEY_IP_TOTLEN] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "ip.totlen", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_totalLengthIPv4,
		},
	},
	[KEY_IP_IHL] = {
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "ip.ihl", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_internetHeaderLengthIPv4,
		},
	},
	[KEY_IP_CSUM] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "ip.csum", 
	},
	[KEY_IP_ID] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "ip.id", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_identificationIPv4,
		},
	},
	[KEY_IP_FRAGOFF] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "ip.fragoff", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_fragmentOffsetIPv4,
		},
	},
	[KEY_IP6_SADDR] = {
		.type = ULOGD_RET_RAW,
		.flags = ULOGD_RETF_NONE,
		.name = "ip6.saddr",
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_sourceIPv6Address,
		},
	},
	[KEY_IP6_DADDR] = {
		.type = ULOGD_RET_RAW,
		.flags = ULOGD_RETF_NONE,
		.name = "ip6.daddr",
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_destinationIPv6Address,
		},
	},
	[KEY_IP6_PAYLOAD_LEN] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "ip6.payload_len",
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_payloadLengthIPv6,
		},
	},
	[KEY_IP6_PRIORITY] = {
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "ip6.priority",
	},
	[KEY_IP6_FLOWLABEL] = {
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "ip6.flowlabel",
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_flowLabelIPv6,
		},
	},
	[KEY_IP6_HOPLIMIT] = {
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "ip6.hoplimit",
	},
	[KEY_IP6_NEXTHDR] = {
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "ip6.nexthdr",
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_nextHeaderIPv6,
		},
	},
	[KEY_IP6_FRAG_OFF] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "ip6.fragoff",
	},
	[KEY_IP6_FRAG_ID] = {
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "ip6.fragid",
	},
	[KEY_TCP_SPORT] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.sport", 
		.ipfix = { 
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_tcpSourcePort,
		},
	},
	[KEY_TCP_DPORT] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.dport", 
		.ipfix = { 
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_tcpDestinationPort,
		},
	},
	[KEY_TCP_SEQ] = {
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.seq", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_tcpSequenceNumber,
		},
	},
	[KEY_TCP_ACKSEQ] = {
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.ackseq", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_tcpAcknowledgementNumber,
		},
	},
	[KEY_TCP_OFFSET] = {
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE, 
		.name = "tcp.offset",
	},
	[KEY_TCP_RESERVED] = {
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.reserved",
	}, 
	[KEY_TCP_WINDOW] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.window",
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_tcpWindowSize,
		},
	},
	[KEY_TCP_URG] = {
		.type = ULOGD_RET_BOOL, 
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.urg", 
	},
	[KEY_TCP_URGP] = {
		.type = ULOGD_RET_UINT16, 
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.urgp",
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_tcpUrgentPointer,
		},
	},
	[KEY_TCP_ACK] = {
		.type = ULOGD_RET_BOOL, 
		.flags = ULOGD_RETF_NONE, 
		.name = "tcp.ack", 
	},
	[KEY_TCP_PSH] = {
		.type = ULOGD_RET_BOOL,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.psh",
	},
	[KEY_TCP_RST] = {
		.type = ULOGD_RET_BOOL,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.rst",
	},
	[KEY_TCP_SYN] = {
		.type = ULOGD_RET_BOOL,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.syn",
	},
	[KEY_TCP_FIN] = {
		.type = ULOGD_RET_BOOL,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.fin",
	},
	[KEY_TCP_RES1] = {
		.type = ULOGD_RET_BOOL,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.res1",
	},
	[KEY_TCP_RES2] = {
		.type = ULOGD_RET_BOOL,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.res2",
	},
	[KEY_TCP_CSUM] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "tcp.csum",
	},
	[KEY_UDP_SPORT] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "udp.sport", 
		.ipfix = { 
			.vendor = IPFIX_VENDOR_IETF, 
			.field_id = IPFIX_udpSourcePort,
		},
	},
	[KEY_UDP_DPORT] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "udp.dport", 
		.ipfix = { 
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_udpDestinationPort,
		},
	},
	[KEY_UDP_LEN] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "udp.len", 
	},
	[KEY_UDP_CSUM] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "udp.csum",
	},
	[KEY_ICMP_TYPE] = {
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "icmp.type", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_icmpTypeIPv4,
		},
	},
	[KEY_ICMP_CODE] = {
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "icmp.code", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_icmpCodeIPv4,
		},
	},
	[KEY_ICMP_ECHOID] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "icmp.echoid", 
	},
	[KEY_ICMP_ECHOSEQ] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "icmp.echoseq",
	},
	[KEY_ICMP_GATEWAY] = {
		.type = ULOGD_RET_IPADDR,
		.flags = ULOGD_RETF_NONE,
		.name = "icmp.gateway", 
	},
	[KEY_ICMP_FRAGMTU] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "icmp.fragmtu", 
	},
	[KEY_ICMP_CSUM] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "icmp.csum",
	},
	[KEY_ICMPV6_TYPE] = {
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "icmpv6.type", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_icmpTypeIPv6,
		},
	},
	[KEY_ICMPV6_CODE] = {
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "icmpv6.code", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_icmpCodeIPv6,
		},
	},
	[KEY_ICMPV6_ECHOID] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "icmpv6.echoid", 
	},
	[KEY_ICMPV6_ECHOSEQ] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "icmpv6.echoseq",
	},
	[KEY_ICMPV6_CSUM] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "icmpv6.csum",
	},
	[KEY_AHESP_SPI] = {
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "ahesp.spi",
	},

};

/***********************************************************************
 * 			TCP HEADER
 ***********************************************************************/

static int _interp_tcp(struct ulogd_pluginstance *pi, struct tcphdr *tcph,
		       u_int32_t len)
{
	struct ulogd_key *ret = pi->output.keys;

	if (len < sizeof(struct tcphdr))
		return 0;
	
	ret[KEY_TCP_SPORT].u.value.ui16 = ntohs(tcph->source);
	ret[KEY_TCP_SPORT].flags |= ULOGD_RETF_VALID;
	ret[KEY_TCP_DPORT].u.value.ui16 = ntohs(tcph->dest);
	ret[KEY_TCP_DPORT].flags |= ULOGD_RETF_VALID;
	ret[KEY_TCP_SEQ].u.value.ui32 = ntohl(tcph->seq);
	ret[KEY_TCP_SEQ].flags |= ULOGD_RETF_VALID;
	ret[KEY_TCP_ACKSEQ].u.value.ui32 = ntohl(tcph->ack_seq);
	ret[KEY_TCP_ACKSEQ].flags |= ULOGD_RETF_VALID;
	ret[KEY_TCP_OFFSET].u.value.ui8 = ntohs(tcph->doff);
	ret[KEY_TCP_OFFSET].flags |= ULOGD_RETF_VALID;
	ret[KEY_TCP_RESERVED].u.value.ui8 = ntohs(tcph->res1);
	ret[KEY_TCP_RESERVED].flags |= ULOGD_RETF_VALID;
	ret[KEY_TCP_WINDOW].u.value.ui16 = ntohs(tcph->window);
	ret[KEY_TCP_WINDOW].flags |= ULOGD_RETF_VALID;

	ret[KEY_TCP_URG].u.value.b = tcph->urg;
	ret[KEY_TCP_URG].flags |= ULOGD_RETF_VALID;
	if (tcph->urg) {
		ret[KEY_TCP_URGP].u.value.ui16 = ntohs(tcph->urg_ptr);
		ret[KEY_TCP_URGP].flags |= ULOGD_RETF_VALID;
	}
	ret[KEY_TCP_ACK].u.value.b = tcph->ack;
	ret[KEY_TCP_ACK].flags |= ULOGD_RETF_VALID;
	ret[KEY_TCP_PSH].u.value.b = tcph->psh;
	ret[KEY_TCP_PSH].flags |= ULOGD_RETF_VALID;
	ret[KEY_TCP_RST].u.value.b = tcph->rst;
	ret[KEY_TCP_RST].flags |= ULOGD_RETF_VALID;
	ret[KEY_TCP_SYN].u.value.b = tcph->syn;
	ret[KEY_TCP_SYN].flags |= ULOGD_RETF_VALID;
	ret[KEY_TCP_FIN].u.value.b = tcph->fin;
	ret[KEY_TCP_FIN].flags |= ULOGD_RETF_VALID;
	ret[KEY_TCP_RES1].u.value.b = tcph->res1;
	ret[KEY_TCP_RES1].flags |= ULOGD_RETF_VALID;
	ret[KEY_TCP_RES2].u.value.b = tcph->res2;
	ret[KEY_TCP_RES2].flags |= ULOGD_RETF_VALID;
	ret[KEY_TCP_CSUM].u.value.ui16 = ntohs(tcph->check);
	ret[KEY_TCP_CSUM].u.value.ui16 = ULOGD_RETF_VALID;
	
	return 0;
}

/***********************************************************************
 * 			UDP HEADER
 ***********************************************************************/

static int _interp_udp(struct ulogd_pluginstance *pi, struct udphdr *udph,
		       u_int32_t len)
		
{
	struct ulogd_key *ret = pi->output.keys;

	if (len < sizeof(struct udphdr))
		return 0;

	ret[KEY_UDP_SPORT].u.value.ui16 = ntohs(udph->source);
	ret[KEY_UDP_SPORT].flags |= ULOGD_RETF_VALID;
	ret[KEY_UDP_DPORT].u.value.ui16 = ntohs(udph->dest);
	ret[KEY_UDP_DPORT].flags |= ULOGD_RETF_VALID;
	ret[KEY_UDP_LEN].u.value.ui16 = ntohs(udph->len);
	ret[KEY_UDP_LEN].flags |= ULOGD_RETF_VALID;
	ret[KEY_UDP_CSUM].u.value.ui16 = ntohs(udph->check);
	ret[KEY_UDP_CSUM].flags |= ULOGD_RETF_VALID;
	
	return 0;
}

/***********************************************************************
 * 			ICMP HEADER
 ***********************************************************************/

static int _interp_icmp(struct ulogd_pluginstance *pi, struct icmphdr *icmph,
			u_int32_t len)
{
	struct ulogd_key *ret = pi->output.keys;

	if (len < sizeof(struct icmphdr))
		return 0;

	ret[KEY_ICMP_TYPE].u.value.ui8 = icmph->type;
	ret[KEY_ICMP_TYPE].flags |= ULOGD_RETF_VALID;
	ret[KEY_ICMP_CODE].u.value.ui8 = icmph->code;
	ret[KEY_ICMP_CODE].flags |= ULOGD_RETF_VALID;

	switch (icmph->type) {
	case ICMP_ECHO:
	case ICMP_ECHOREPLY:
		ret[KEY_ICMP_ECHOID].u.value.ui16 = ntohs(icmph->un.echo.id);
		ret[KEY_ICMP_ECHOID].flags |= ULOGD_RETF_VALID;
		ret[KEY_ICMP_ECHOSEQ].u.value.ui16 = ntohs(icmph->un.echo.sequence);
		ret[KEY_ICMP_ECHOSEQ].flags |= ULOGD_RETF_VALID;
		break;
	case ICMP_REDIRECT:
	case ICMP_PARAMETERPROB:
		ret[KEY_ICMP_GATEWAY].u.value.ui32 = ntohl(icmph->un.gateway);
		ret[KEY_ICMP_GATEWAY].flags |= ULOGD_RETF_VALID;
		break;
	case ICMP_DEST_UNREACH:
		if (icmph->code == ICMP_FRAG_NEEDED) {
			ret[KEY_ICMP_FRAGMTU].u.value.ui16 = ntohs(icmph->un.frag.mtu);
			ret[KEY_ICMP_FRAGMTU].flags |= ULOGD_RETF_VALID;
		}
		break;
	}
	ret[KEY_ICMP_CSUM].u.value.ui16 = icmph->checksum;
	ret[KEY_ICMP_CSUM].flags |= ULOGD_RETF_VALID;

	return 0;
}

/***********************************************************************
 * 			ICMPv6 HEADER
 ***********************************************************************/

static int _interp_icmpv6(struct ulogd_pluginstance *pi, struct icmp6_hdr *icmph,
			  u_int32_t len)
{
	struct ulogd_key *ret = pi->output.keys;

	if (len < sizeof(struct icmp6_hdr))
		return 0;

	ret[KEY_ICMPV6_TYPE].u.value.ui8 = icmph->icmp6_type;
	ret[KEY_ICMPV6_TYPE].flags |= ULOGD_RETF_VALID;
	ret[KEY_ICMPV6_CODE].u.value.ui8 = icmph->icmp6_code;
	ret[KEY_ICMPV6_CODE].flags |= ULOGD_RETF_VALID;

	switch (icmph->icmp6_type) {
	case ICMP6_ECHO_REQUEST:
	case ICMP6_ECHO_REPLY:
		ret[KEY_ICMPV6_ECHOID].u.value.ui16 = ntohs(icmph->icmp6_id);
		ret[KEY_ICMPV6_ECHOID].flags |= ULOGD_RETF_VALID;
		ret[KEY_ICMPV6_ECHOSEQ].u.value.ui16 = ntohs(icmph->icmp6_seq);
		ret[KEY_ICMPV6_ECHOSEQ].flags |= ULOGD_RETF_VALID;
		break;
	}
	ret[KEY_ICMPV6_CSUM].u.value.ui16 = icmph->icmp6_cksum;
	ret[KEY_ICMPV6_CSUM].flags |= ULOGD_RETF_VALID;

	return 0;
}


/***********************************************************************
 * 			IPSEC HEADER 
 ***********************************************************************/
static int _interp_ahesp(struct ulogd_pluginstance *pi, void *protoh,
			 u_int32_t len)
{
#if 0
	struct ulogd_key *ret = pi->output.keys;
	struct esphdr *esph = protoh;

	if (len < sizeof(struct esphdr))
		return 0;

	ret[KEY_AHESP_SPI].u.value.ui32 = ntohl(esph->spi);
	ret[KEY_AHESP_SPI].flags |= ULOGD_RETF_VALID;
#endif

	return 0;
}

/***********************************************************************
 * 			IP HEADER
 ***********************************************************************/

static int _interp_iphdr(struct ulogd_pluginstance *pi, u_int32_t len)
{
	struct ulogd_key *ret = pi->output.keys;
	struct iphdr *iph = pi->input.keys[0].u.source->u.value.ptr;
	void *nexthdr = (u_int32_t *)iph + iph->ihl;

	if (len < sizeof(struct iphdr) || len <= iph->ihl * 4)
		return 0;
	len -= iph->ihl * 4;

	ret[KEY_IP_SADDR].u.value.ui32 = iph->saddr;
	ret[KEY_IP_SADDR].flags |= ULOGD_RETF_VALID;
	ret[KEY_IP_DADDR].u.value.ui32 = iph->daddr;
	ret[KEY_IP_DADDR].flags |= ULOGD_RETF_VALID;
	ret[KEY_IP_PROTOCOL].u.value.ui8 = iph->protocol;
	ret[KEY_IP_PROTOCOL].flags |= ULOGD_RETF_VALID;
	ret[KEY_IP_TOS].u.value.ui8 = iph->tos;
	ret[KEY_IP_TOS].flags |= ULOGD_RETF_VALID;
	ret[KEY_IP_TTL].u.value.ui8 = iph->ttl;
	ret[KEY_IP_TTL].flags |= ULOGD_RETF_VALID;
	ret[KEY_IP_TOTLEN].u.value.ui16 = ntohs(iph->tot_len);
	ret[KEY_IP_TOTLEN].flags |= ULOGD_RETF_VALID;
	ret[KEY_IP_IHL].u.value.ui8 = iph->ihl;
	ret[KEY_IP_IHL].flags |= ULOGD_RETF_VALID;
	ret[KEY_IP_CSUM].u.value.ui16 = ntohs(iph->check);
	ret[KEY_IP_CSUM].flags |= ULOGD_RETF_VALID;
	ret[KEY_IP_ID].u.value.ui16 = ntohs(iph->id);
	ret[KEY_IP_ID].flags |= ULOGD_RETF_VALID;
	ret[KEY_IP_FRAGOFF].u.value.ui16 = ntohs(iph->frag_off);
	ret[KEY_IP_FRAGOFF].flags |= ULOGD_RETF_VALID;

	switch (iph->protocol) {
	case IPPROTO_TCP:
		_interp_tcp(pi, nexthdr, len);
		break;
	case IPPROTO_UDP:
		_interp_udp(pi, nexthdr, len);
		break;
	case IPPROTO_ICMP:
		_interp_icmp(pi, nexthdr, len);
		break;
	case IPPROTO_AH:
	case IPPROTO_ESP:
		_interp_ahesp(pi, nexthdr, len);
		break;
	}

	return 0;
}

/***********************************************************************
 * 			IPv6 HEADER
 ***********************************************************************/

static int ip6_ext_hdr(u_int8_t nexthdr)
{
	switch (nexthdr) {
	case IPPROTO_HOPOPTS:
	case IPPROTO_ROUTING:
	case IPPROTO_FRAGMENT:
	case IPPROTO_ESP:
	case IPPROTO_AH:
	case IPPROTO_DSTOPTS:
		return 1;
	default:
		return 0;
	}
}

static int _interp_ipv6hdr(struct ulogd_pluginstance *pi, u_int32_t len)
{
	struct ulogd_key *ret = pi->output.keys;
	struct ip6_hdr *ipv6h = pi->input.keys[0].u.source->u.value.ptr;
	unsigned int ptr, hdrlen = 0;
	u_int8_t curhdr;
	int fragment = 0;

	if (len < sizeof(struct ip6_hdr))
		return 0;

	ret[KEY_IP6_SADDR].u.value.ptr = &ipv6h->ip6_src;
	ret[KEY_IP6_SADDR].flags |= ULOGD_RETF_VALID;
	ret[KEY_IP6_DADDR].u.value.ptr = &ipv6h->ip6_dst;
	ret[KEY_IP6_DADDR].flags |= ULOGD_RETF_VALID;
	ret[KEY_IP6_PAYLOAD_LEN].u.value.ui16 = ntohs(ipv6h->ip6_plen);
	ret[KEY_IP6_PAYLOAD_LEN].flags |= ULOGD_RETF_VALID;
	ret[KEY_IP6_PRIORITY].u.value.ui8 = ntohl(ipv6h->ip6_flow & 0x0ff00000) >> 20;
	ret[KEY_IP6_PRIORITY].flags |= ULOGD_RETF_VALID;
	ret[KEY_IP6_FLOWLABEL].u.value.ui32 = ntohl(ipv6h->ip6_flow & 0x000fffff);
	ret[KEY_IP6_FLOWLABEL].flags |= ULOGD_RETF_VALID;
	ret[KEY_IP6_HOPLIMIT].u.value.ui8 = ipv6h->ip6_hlim;
	ret[KEY_IP6_HOPLIMIT].flags |= ULOGD_RETF_VALID;

	curhdr = ipv6h->ip6_nxt;
	ptr = sizeof(struct ip6_hdr);
	len -= sizeof(struct ip6_hdr);

	while (curhdr != IPPROTO_NONE && ip6_ext_hdr(curhdr)) {
		struct ip6_ext *ext = (void *)ipv6h + ptr;

		if (len < sizeof(struct ip6_ext))
			return 0;

		switch (curhdr) {
		case IPPROTO_FRAGMENT: {
			struct ip6_frag *fh = (struct ip6_frag *)ext;

			hdrlen = sizeof(struct ip6_frag);
			if (len < hdrlen)
				return 0;
			len -= hdrlen;

			ret[KEY_IP6_FRAG_OFF].u.value.ui16 = ntohs(fh->ip6f_offlg & IP6F_OFF_MASK);
			ret[KEY_IP6_FRAG_OFF].flags |= ULOGD_RETF_VALID;
			ret[KEY_IP6_FRAG_ID].u.value.ui32 = ntohl(fh->ip6f_ident);
			ret[KEY_IP6_FRAG_ID].flags |= ULOGD_RETF_VALID;

			if (ntohs(fh->ip6f_offlg & IP6F_OFF_MASK))
				fragment = 1;
			break;
		}
		case IPPROTO_DSTOPTS:
		case IPPROTO_ROUTING:
		case IPPROTO_HOPOPTS:
			if (fragment)
				goto out;

			hdrlen = (ext->ip6e_len + 1) << 3;
			if (len < hdrlen)
				return 0;
			len -= hdrlen;
			break;
		case IPPROTO_AH:
			if (fragment)
				goto out;

			hdrlen = (ext->ip6e_len + 2) << 2;
			if (len < hdrlen)
				return 0;
			len -= hdrlen;

			_interp_ahesp(pi, (void *)ext, len);
			break;
		case IPPROTO_ESP:
			if (fragment)
				goto out;

			hdrlen = (ext->ip6e_len + 2) << 2;
			if (len < hdrlen)
				return 0;
			len -= hdrlen;

			_interp_ahesp(pi, (void *)ext, len);
			goto out;
		default:
			return 0;
		}

		curhdr = ext->ip6e_nxt;
		ptr += hdrlen;
	}

	if (fragment)
		goto out;

	switch (curhdr) {
	case IPPROTO_TCP:
		_interp_tcp(pi, (void *)ipv6h + ptr, len);
		break;
	case IPPROTO_UDP:
		_interp_udp(pi, (void *)ipv6h + ptr, len);
		break;
	case IPPROTO_ICMPV6:
		_interp_icmpv6(pi, (void *)ipv6h + ptr, len);
		break;
	}

out:
	ret[KEY_IP6_NEXTHDR].u.value.ui8 = curhdr;
	ret[KEY_IP6_NEXTHDR].flags |= ULOGD_RETF_VALID;
	return 0;
}

static int _interp_pkt(struct ulogd_pluginstance *pi)
{
	u_int32_t len = pi->input.keys[1].u.source->u.value.ui32;
	u_int8_t family = pi->input.keys[2].u.source->u.value.ui8;

	switch (family) {
	case AF_INET:
		return _interp_iphdr(pi, len);
	case AF_INET6:
		return _interp_ipv6hdr(pi, len);
	}
	return 0;
}

static struct ulogd_key base_inp[] = {
	{ 
		.type = ULOGD_RET_RAW,
		.name = "raw.pkt", 
		.ipfix = { 
			.vendor = IPFIX_VENDOR_NETFILTER, 
			.field_id = IPFIX_NF_rawpacket,
		},
	},
	{
		.type = ULOGD_RET_UINT32,
		.name = "raw.pktlen", 
		.ipfix = {
			.vendor = IPFIX_VENDOR_NETFILTER, 
			.field_id = IPFIX_NF_rawpacket_length,
		},
	},
	{
		.type = ULOGD_RET_UINT8,
		.name = "oob.family",
	}
};

static struct ulogd_plugin base_plugin = {
	.name = "BASE",
	.input = {
		.keys = base_inp,
		.num_keys = ARRAY_SIZE(base_inp),
		.type = ULOGD_DTYPE_RAW,
		},
	.output = {
		.keys = iphdr_rets,
		.num_keys = ARRAY_SIZE(iphdr_rets),
		.type = ULOGD_DTYPE_PACKET,
		},
	.interp = &_interp_pkt,
	.version = ULOGD_VERSION,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	ulogd_register_plugin(&base_plugin);
}
