/* printpkt.c
 *
 * build something looking like a iptables LOG message
 *
 * (C) 2000-2003 by Harald Welte <laforge@gnumonks.org>
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
 *
 * $Id$
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <ulogd/ulogd.h>
#include <ulogd/conffile.h>
#include <ulogd/printpkt.h>
#include <netinet/if_ether.h>

struct ulogd_key printpkt_keys[] = {
	[KEY_OOB_FAMILY]	= { .name = "oob.family", },
	[KEY_OOB_PROTOCOL]	= { .name = "oob.protocol", },
	[KEY_OOB_TIME_SEC]	= { .name = "oob.time.sec", },
	[KEY_OOB_PREFIX]	= { .name = "oob.prefix", },
	[KEY_OOB_IN]		= { .name = "oob.in", },
	[KEY_OOB_OUT]		= { .name = "oob.out", },
	[KEY_OOB_UID]		= { .name = "oob.uid",
				    .flags = ULOGD_KEYF_OPTIONAL
				  },
	[KEY_RAW_MAC]		= { .name = "raw.mac", },
	[KEY_RAW_MACLEN]	= { .name = "raw.mac_len", },
	[KEY_IP_SADDR]		= { .name = "ip.saddr.str", },
	[KEY_IP_DADDR]		= { .name = "ip.daddr.str", },
	[KEY_IP_TOTLEN]		= { .name = "ip.totlen", },
	[KEY_IP_TOS]		= { .name = "ip.tos", },
	[KEY_IP_TTL]		= { .name = "ip.ttl", },
	[KEY_IP_ID]		= { .name = "ip.id", },
	[KEY_IP_FRAGOFF]	= { .name = "ip.fragoff", },
	[KEY_IP_PROTOCOL]	= { .name = "ip.protocol", },
	[KEY_IP6_PAYLOAD_LEN]	= { .name = "ip6.payload_len" },
	[KEY_IP6_PRIORITY]	= { .name = "ip6.priority" },
	[KEY_IP6_HOPLIMIT]	= { .name = "ip6.hoplimit" },
	[KEY_IP6_FLOWLABEL]	= { .name = "ip6.flowlabel" },
	[KEY_IP6_NEXTHDR]	= { .name = "ip6.nexthdr" },
	[KEY_IP6_FRAG_OFF]	= { .name = "ip6.fragoff" },
	[KEY_IP6_FRAG_ID]	= { .name = "ip6.fragid" },
	[KEY_TCP_SPORT]		= { .name = "tcp.sport", },
	[KEY_TCP_DPORT]		= { .name = "tcp.dport", },
	[KEY_TCP_SEQ]		= { .name = "tcp.seq", },
	[KEY_TCP_ACKSEQ]	= { .name = "tcp.ackseq", },
	[KEY_TCP_WINDOW]	= { .name = "tcp.window", },
	[KEY_TCP_SYN]		= { .name = "tcp.syn", },
	[KEY_TCP_ACK]		= { .name = "tcp.ack", },
	[KEY_TCP_URG]		= { .name = "tcp.urg", },
	[KEY_TCP_PSH]		= { .name = "tcp.psh", },
	[KEY_TCP_RST]		= { .name = "tcp.rst", },
	[KEY_TCP_FIN]		= { .name = "tcp.fin", },
	[KEY_TCP_URG]		= { .name = "tcp.urg", },
	[KEY_TCP_URGP]		= { .name = "tcp.urgp", },
	[KEY_UDP_SPORT]		= { .name = "udp.sport", },
	[KEY_UDP_DPORT]		= { .name = "udp.dport", },
	[KEY_UDP_LEN]		= { .name = "udp.len", },
	[KEY_ICMP_TYPE]		= { .name = "icmp.type", },
	[KEY_ICMP_CODE]		= { .name = "icmp.code", },
	[KEY_ICMP_ECHOID]	= { .name = "icmp.echoid", },
	[KEY_ICMP_ECHOSEQ]	= { .name = "icmp.echoseq", },
	[KEY_ICMP_GATEWAY]	= { .name = "icmp.gateway", },
	[KEY_ICMP_FRAGMTU]	= { .name = "icmp.fragmtu", },
	[KEY_ICMPV6_TYPE]	= { .name = "icmpv6.type", },
	[KEY_ICMPV6_CODE]	= { .name = "icmpv6.code", },
	[KEY_ICMPV6_ECHOID]	= { .name = "icmpv6.echoid", },
	[KEY_ICMPV6_ECHOSEQ]	= { .name = "icmpv6.echoseq", },
	[KEY_AHESP_SPI]		= { .name = "ahesp.spi", },
	[KEY_ARP_HTYPE]         = { .name = "arp.hwtype", },
	[KEY_ARP_PTYPE]         = { .name = "arp.protocoltype", },
	[KEY_ARP_OPCODE]        = { .name = "arp.operation", },
	[KEY_ARP_SHA]           = { .name = "arp.shwaddr", },
	[KEY_ARP_SPA]           = { .name = "arp.saddr.str", },
	[KEY_ARP_THA]           = { .name = "arp.dhwaddr", },
	[KEY_ARP_TPA]           = { .name = "arp.daddr.str", },

};

static int printpkt_proto(struct ulogd_key *res, char *buf, int protocol)
{
	char *buf_cur = buf;

	switch (protocol) {
	case IPPROTO_TCP:
		buf_cur += sprintf(buf_cur, "PROTO=KEY_TCP ");

		if (!pp_is_valid(res, KEY_TCP_SPORT)) {
			buf_cur += sprintf(buf_cur, "INCOMPLETE");
			break;
		}

		buf_cur += sprintf(buf_cur, "SPT=%u DPT=%u ",
				   GET_VALUE(res, KEY_TCP_SPORT).ui16,
				   GET_VALUE(res, KEY_TCP_DPORT).ui16);
		/* FIXME: config */
		buf_cur += sprintf(buf_cur, "SEQ=%u ACK=%u ", 
				   GET_VALUE(res, KEY_TCP_SEQ).ui32,
				   GET_VALUE(res, KEY_TCP_ACKSEQ).ui32);

		buf_cur += sprintf(buf_cur, "WINDOW=%u ",
				   GET_VALUE(res, KEY_TCP_WINDOW).ui16);

//		buf_cur += sprintf(buf_cur, "RES=0x%02x ", 
		
		if (GET_VALUE(res, KEY_TCP_URG).b)
			buf_cur += sprintf(buf_cur, "URG ");

		if (GET_VALUE(res, KEY_TCP_ACK).b)
			buf_cur += sprintf(buf_cur, "ACK ");

		if (GET_VALUE(res, KEY_TCP_PSH).b)
			buf_cur += sprintf(buf_cur, "PSH ");

		if (GET_VALUE(res, KEY_TCP_RST).b)
			buf_cur += sprintf(buf_cur, "RST ");

		if (GET_VALUE(res, KEY_TCP_SYN).b)
			buf_cur += sprintf(buf_cur, "SYN ");

		if (GET_VALUE(res, KEY_TCP_FIN).b)
			buf_cur += sprintf(buf_cur, "FIN ");

		buf_cur += sprintf(buf_cur, "URGP=%u ",
				   GET_VALUE(res, KEY_TCP_URGP).ui16);

		break;

	case IPPROTO_UDP:
		buf_cur += sprintf(buf_cur, "PROTO=KEY_UDP ");

		if (!pp_is_valid(res, KEY_UDP_SPORT)) {
			buf_cur += sprintf(buf_cur, "INCOMPLETE");
			break;
		}

		buf_cur += sprintf(buf_cur, "SPT=%u DPT=%u LEN=%u ", 
				   GET_VALUE(res, KEY_UDP_SPORT).ui16,
				   GET_VALUE(res, KEY_UDP_DPORT).ui16, 
				   GET_VALUE(res, KEY_UDP_LEN).ui16);
		break;
	case IPPROTO_ESP:
	case IPPROTO_AH:
		buf_cur += sprintf(buf_cur, "PROTO=%s ",
				   GET_VALUE(res, KEY_IP_PROTOCOL).ui8 == IPPROTO_ESP ? "ESP" : "AH");

		if (!pp_is_valid(res, KEY_AHESP_SPI)) {
			buf_cur += sprintf(buf_cur, "INCOMPLETE");
			break;
		}

		buf_cur += sprintf(buf_cur, "SPI=0x%x ",
				   GET_VALUE(res, KEY_AHESP_SPI).ui32);
		break;
	}

	return buf_cur - buf;
}

static int printpkt_ipv4(struct ulogd_key *res, char *buf)
{
	char *buf_cur = buf;
	char tmp[INET_ADDRSTRLEN];

	if (pp_is_valid(res, KEY_IP_SADDR))
		buf_cur += sprintf(buf_cur, "SRC=%s ",
				   GET_VALUE(res, KEY_IP_SADDR).ptr);

	if (pp_is_valid(res, KEY_IP_DADDR))
		buf_cur += sprintf(buf_cur, "DST=%s ",
				   GET_VALUE(res, KEY_IP_DADDR).ptr);

	/* FIXME: add pp_is_valid calls to remainder of file */
	buf_cur += sprintf(buf_cur,"LEN=%u TOS=%02X PREC=0x%02X TTL=%u ID=%u ", 
			   GET_VALUE(res, KEY_IP_TOTLEN).ui16,
			   GET_VALUE(res, KEY_IP_TOS).ui8 & IPTOS_TOS_MASK, 
			   GET_VALUE(res, KEY_IP_TOS).ui8 & IPTOS_PREC_MASK,
			   GET_VALUE(res, KEY_IP_TTL).ui8,
			   GET_VALUE(res, KEY_IP_ID).ui16);

	if (GET_VALUE(res, KEY_IP_FRAGOFF).ui16 & IP_RF) 
		buf_cur += sprintf(buf_cur, "CE ");

	if (GET_VALUE(res, KEY_IP_FRAGOFF).ui16 & IP_DF)
		buf_cur += sprintf(buf_cur, "DF ");

	if (GET_VALUE(res, KEY_IP_FRAGOFF).ui16 & IP_MF)
		buf_cur += sprintf(buf_cur, "MF ");

	if (GET_VALUE(res, KEY_IP_FRAGOFF).ui16 & IP_OFFMASK)
		buf_cur += sprintf(buf_cur, "FRAG:%u ", 
				   GET_VALUE(res, KEY_IP_FRAGOFF).ui16 & IP_OFFMASK);

	switch (GET_VALUE(res, KEY_IP_PROTOCOL).ui8) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_ESP:
	case IPPROTO_AH:
		buf_cur += printpkt_proto(res, buf_cur,
					  GET_VALUE(res, KEY_IP_PROTOCOL).ui8);
		break;

	case IPPROTO_ICMP:
		buf_cur += sprintf(buf_cur, "PROTO=ICMP ");

		if (!pp_is_valid(res, KEY_ICMP_TYPE)) {
			buf_cur += sprintf(buf_cur, "INCOMPLETE");
			break;
		}

		buf_cur += sprintf(buf_cur, "TYPE=%u CODE=%u ",
				   GET_VALUE(res, KEY_ICMP_TYPE).ui8,
				   GET_VALUE(res, KEY_ICMP_CODE).ui8);

		switch (GET_VALUE(res, KEY_ICMP_TYPE).ui8) {
		case ICMP_ECHO:
		case ICMP_ECHOREPLY:
			buf_cur += sprintf(buf_cur, "ID=%u SEQ=%u ", 
					   GET_VALUE(res, KEY_ICMP_ECHOID).ui16,
					   GET_VALUE(res, KEY_ICMP_ECHOSEQ).ui16);
			break;
		case ICMP_PARAMETERPROB:
			buf_cur += sprintf(buf_cur, "PARAMETER=%u ",
					   GET_VALUE(res, KEY_ICMP_GATEWAY).ui32 >> 24);
			break;
		case ICMP_REDIRECT:
			buf_cur += sprintf(buf_cur, "GATEWAY=%s ",
					   inet_ntop(AF_INET,
					   	     &GET_VALUE(res, KEY_ICMP_GATEWAY).ui32,
						     tmp, sizeof(tmp)));
			break;
		case ICMP_DEST_UNREACH:
			if (GET_VALUE(res, KEY_ICMP_CODE).ui8 == ICMP_FRAG_NEEDED)
				buf_cur += sprintf(buf_cur, "MTU=%u ", 
						   GET_VALUE(res, KEY_ICMP_FRAGMTU).ui16);
			break;
		}
		break;
	default:
		buf_cur += sprintf(buf_cur, "PROTO=%u ",
				   GET_VALUE(res, KEY_IP_PROTOCOL).ui8);
	}

	return buf_cur - buf;
}

static int printpkt_ipv6(struct ulogd_key *res, char *buf)
{
	char *buf_cur = buf;
	char tmp[INET6_ADDRSTRLEN];

	if (pp_is_valid(res, KEY_IP_SADDR))
		buf_cur += sprintf(buf_cur, "SRC=%s ",
				   GET_VALUE(res, KEY_IP_SADDR).ptr);

	if (pp_is_valid(res, KEY_IP_DADDR))
		buf_cur += sprintf(buf_cur, "DST=%s ",
				   GET_VALUE(res, KEY_IP_DADDR).ptr);

	if (pp_is_valid(res, KEY_IP6_PAYLOAD_LEN))
		buf_cur += sprintf(buf_cur, "LEN=%Zu ",
				   GET_VALUE(res, KEY_IP6_PAYLOAD_LEN).ui16 +
				   sizeof(struct ip6_hdr));

	if (pp_is_valid(res, KEY_IP6_PRIORITY))
		buf_cur += sprintf(buf_cur, "TC=%u ",
				   GET_VALUE(res, KEY_IP6_PRIORITY).ui8);

	if (pp_is_valid(res, KEY_IP6_HOPLIMIT))
		buf_cur += sprintf(buf_cur, "HOPLIMIT=%u ",
				   GET_VALUE(res, KEY_IP6_HOPLIMIT).ui8);
	
	if (pp_is_valid(res, KEY_IP6_FLOWLABEL))
		buf_cur += sprintf(buf_cur, "FLOWLBL=%u ",
				   GET_VALUE(res, KEY_IP6_FLOWLABEL).ui32);

	if (pp_is_valid(res, KEY_IP6_FRAG_OFF) && pp_is_valid(res, KEY_IP6_FRAG_ID))
		buf_cur += sprintf(buf_cur, "FRAG: %u ID: %08x ",
				   GET_VALUE(res, KEY_IP6_FRAG_OFF).ui16,
				   GET_VALUE(res, KEY_IP6_FRAG_ID).ui32);

	switch (GET_VALUE(res, KEY_IP6_NEXTHDR).ui8) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_ESP:
	case IPPROTO_AH:
		buf_cur += printpkt_proto(res, buf_cur,
					  GET_VALUE(res, KEY_IP6_NEXTHDR).ui8);
		break;
	case IPPROTO_ICMPV6:
		buf_cur += sprintf(buf_cur, "PROTO=ICMPv6 ");

		if (!pp_is_valid(res, KEY_ICMPV6_TYPE)) {
			buf_cur += sprintf(buf_cur, "INCOMPLETE");
			break;
		}

		if (!(pp_is_valid(res, KEY_ICMPV6_TYPE) &&
		      pp_is_valid(res, KEY_ICMPV6_CODE))) {
			buf_cur += sprintf(buf_cur, "TRUNCATED");
			break;
		}

		buf_cur += sprintf(buf_cur, "TYPE=%u CODE=%u ",
				   GET_VALUE(res, KEY_ICMPV6_TYPE).ui8,
				   GET_VALUE(res, KEY_ICMPV6_CODE).ui8);

		switch (GET_VALUE(res, KEY_ICMPV6_TYPE).ui8) {
		case ICMP6_ECHO_REQUEST:
		case ICMP6_ECHO_REPLY:
			buf_cur += sprintf(buf_cur, "ID=%u SEQ=%u ", 
					   GET_VALUE(res, KEY_ICMPV6_ECHOID).ui16,
					   GET_VALUE(res, KEY_ICMPV6_ECHOSEQ).ui16);
			break;
		}
		break;
	}

	return buf_cur - buf;
}

int printpkt_arp(struct ulogd_key *res, char *buf)
{
	char *buf_cur = buf;
	u_int16_t code = 0;
	u_int8_t *mac;
	char tmp[INET_ADDRSTRLEN];

	if (pp_is_valid(res, KEY_ARP_SPA))
		buf_cur += sprintf(buf_cur, "SRC=%s ",
				   GET_VALUE(res, KEY_ARP_SPA).ptr);

	if (pp_is_valid(res, KEY_ARP_TPA))
		buf_cur += sprintf(buf_cur, "DST=%s ",
				   GET_VALUE(res, KEY_ARP_TPA).ptr);

	buf_cur += sprintf(buf_cur, "PROTO=ARP ");

	if (pp_is_valid(res, KEY_ARP_OPCODE)) {
		code = GET_VALUE(res, KEY_ARP_OPCODE).ui16;
		switch (code) {
		case ARPOP_REQUEST:
			buf_cur += sprintf(buf_cur, "REQUEST ");
			break;
		case ARPOP_REPLY:
			buf_cur += sprintf(buf_cur, "REPLY ");
			break;
		case ARPOP_NAK:
			buf_cur += sprintf(buf_cur, "NAK ");
			break;
		default:
			buf_cur += sprintf(buf_cur, "CODE=%u ", code);
		}

		if (pp_is_valid(res, KEY_ARP_SHA) && (code == ARPOP_REPLY)) {
			mac = GET_VALUE(res, KEY_ARP_SHA).ptr;
			buf_cur += sprintf(buf_cur, "REPLY_MAC="
					   "%02x:%02x:%02x:%02x:%02x:%02x ",
					   mac[0], mac[1], mac[2],
					   mac[3], mac[4], mac[5]);
		}
	}

	return buf_cur - buf;
}


int printpkt_bridge(struct ulogd_key *res, char *buf)
{
	char *buf_cur = buf;

	switch (GET_VALUE(res, KEY_OOB_PROTOCOL).ui16) {
	case ETH_P_IP:
		buf_cur += printpkt_ipv4(res, buf_cur);
		break;
	case ETH_P_IPV6:
		buf_cur += printpkt_ipv6(res, buf_cur);
		break;
	case ETH_P_ARP:
		buf_cur += printpkt_arp(res, buf_cur);
		break;
	default:
		buf_cur += sprintf(buf_cur, "PROTO=%u ",
			   GET_VALUE(res, KEY_OOB_PROTOCOL).ui16);
	}

	return buf_cur - buf;
}

int printpkt_print(struct ulogd_key *res, char *buf)
{
	char *buf_cur = buf;

	if (pp_is_valid(res, KEY_OOB_PREFIX))
		buf_cur += sprintf(buf_cur, "%s ",
				   (char *) GET_VALUE(res, KEY_OOB_PREFIX).ptr);

	if (pp_is_valid(res, KEY_OOB_IN) && pp_is_valid(res, KEY_OOB_OUT))
		buf_cur += sprintf(buf_cur, "IN=%s OUT=%s ", 
				   (char *) GET_VALUE(res, KEY_OOB_IN).ptr, 
				   (char *) GET_VALUE(res, KEY_OOB_OUT).ptr);

	/* FIXME: configurable */
	if (pp_is_valid(res, KEY_RAW_MAC)) {
		unsigned char *mac = (unsigned char *) GET_VALUE(res, KEY_RAW_MAC).ptr;
		int i, len = GET_VALUE(res, KEY_RAW_MACLEN).ui16;

		buf_cur += sprintf(buf_cur, "MAC=");
		for (i = 0; i < len; i++)
			buf_cur += sprintf(buf_cur, "%02x%c", mac[i],
					   i == len - 1 ? ' ' : ':');
	} else
		buf_cur += sprintf(buf_cur, "MAC= ");

	switch (GET_VALUE(res, KEY_OOB_FAMILY).ui8) {
	case AF_INET:
		buf_cur += printpkt_ipv4(res, buf_cur);
		break;
	case AF_INET6:
		buf_cur += printpkt_ipv6(res, buf_cur);
		break;
	case AF_BRIDGE:
		buf_cur += printpkt_bridge(res, buf_cur);
		break;
	}

	if (pp_is_valid(res, KEY_OOB_UID))
		buf_cur += sprintf(buf_cur, "UID=%d",
				   GET_VALUE(res, KEY_OOB_UID).ui32);

	strcat(buf_cur, "\n");

	return 0;
}
