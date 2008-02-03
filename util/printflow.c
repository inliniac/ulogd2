/* printflow.c
 *
 * build something looking like an iptables LOG message, but for flows
 *
 * (C) 2006 by Philip Craig <philipc@snapgear.com>
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
 * $Id: printflow.c,v 1.1 2006/05/16 01:57:31 philipc Exp $
 *
 */

#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <ulogd/ulogd.h>
#include <ulogd/printflow.h>

enum printflow_fields {
	PRINTFLOW_ORIG_IP_SADDR = 0,
	PRINTFLOW_ORIG_IP_DADDR,
	PRINTFLOW_ORIG_IP_PROTOCOL,
	PRINTFLOW_ORIG_L4_SPORT,
	PRINTFLOW_ORIG_L4_DPORT,
	PRINTFLOW_ORIG_RAW_PKTLEN,
	PRINTFLOW_ORIG_RAW_PKTCOUNT,
	PRINTFLOW_REPLY_IP_SADDR,
	PRINTFLOW_REPLY_IP_DADDR,
	PRINTFLOW_REPLY_IP_PROTOCOL,
	PRINTFLOW_REPLY_L4_SPORT,
	PRINTFLOW_REPLY_L4_DPORT,
	PRINTFLOW_REPLY_RAW_PKTLEN,
	PRINTFLOW_REPLY_RAW_PKTCOUNT,
	PRINTFLOW_ICMP_CODE,
	PRINTFLOW_ICMP_TYPE,
};

struct ulogd_key printflow_keys[FLOW_IDS] = {
	{
		.type = ULOGD_RET_IPADDR,
		.flags = ULOGD_RETF_NONE,
		.name = "orig.ip.saddr",
	},
	{
		.type = ULOGD_RET_IPADDR,
		.flags = ULOGD_RETF_NONE,
		.name = "orig.ip.daddr",
	},
	{
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "orig.ip.protocol",
	},
	{
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "orig.l4.sport",
	},
	{
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "orig.l4.dport",
	},
	{
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "orig.raw.pktlen",
	},
	{
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "orig.raw.pktcount",
	},
	{
		.type = ULOGD_RET_IPADDR,
		.flags = ULOGD_RETF_NONE,
		.name = "reply.ip.saddr",
	},
	{
		.type = ULOGD_RET_IPADDR,
		.flags = ULOGD_RETF_NONE,
		.name = "reply.ip.daddr",
	},
	{
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "reply.ip.protocol",
	},
	{
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "reply.l4.sport",
	},
	{
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "reply.l4.dport",
	},
	{
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "reply.raw.pktlen",
	},
	{
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "reply.raw.pktcount",
	},
	{
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "icmp.code",
	},
	{
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "icmp.type",
	},
};
int printflow_keys_num = sizeof(printflow_keys)/sizeof(*printflow_keys);

#define GET_VALUE(res, x)	(res[x].u.source->u.value)
#define GET_FLAGS(res, x)	(res[x].u.source->flags)
#define pp_is_valid(res, x)	(GET_FLAGS(res, x) & ULOGD_RETF_VALID)

#define pp_print(buf_cur, label, res, x, type) \
	if (pp_is_valid(res, x)) \
		buf_cur += sprintf(buf_cur, label"=%u ", GET_VALUE(res, x).type);

int printflow_print(struct ulogd_key *res, char *buf)
{
	char *buf_cur = buf;

	buf_cur += sprintf(buf_cur, "ORIG: ");

	if (pp_is_valid(res, PRINTFLOW_ORIG_IP_SADDR))
		buf_cur += sprintf(buf_cur, "SRC=%s ", inet_ntoa(
				(struct in_addr) {htonl(GET_VALUE(res, PRINTFLOW_ORIG_IP_SADDR).ui32)}));

	if (pp_is_valid(res, PRINTFLOW_ORIG_IP_DADDR))
		buf_cur += sprintf(buf_cur, "DST=%s ", inet_ntoa(
				(struct in_addr) {htonl(GET_VALUE(res, PRINTFLOW_ORIG_IP_DADDR).ui32)}));

	if (!pp_is_valid(res, PRINTFLOW_ORIG_IP_PROTOCOL))
		goto orig_out;

	switch (GET_VALUE(res, PRINTFLOW_ORIG_IP_PROTOCOL).ui8) {
	case IPPROTO_TCP:
		buf_cur += sprintf(buf_cur, "PROTO=TCP ");
		pp_print(buf_cur, "SPT", res, PRINTFLOW_ORIG_L4_SPORT, ui16);
		pp_print(buf_cur, "DPT", res, PRINTFLOW_ORIG_L4_DPORT, ui16);
		break;

	case IPPROTO_UDP:
		buf_cur += sprintf(buf_cur, "PROTO=UDP ");
		pp_print(buf_cur, "SPT", res, PRINTFLOW_ORIG_L4_SPORT, ui16);
		pp_print(buf_cur, "DPT", res, PRINTFLOW_ORIG_L4_DPORT, ui16);
		break;

	case IPPROTO_ICMP:
		buf_cur += sprintf(buf_cur, "PROTO=ICMP ");
		pp_print(buf_cur, "TYPE", res, PRINTFLOW_ICMP_CODE, ui8);
		pp_print(buf_cur, "CODE", res, PRINTFLOW_ICMP_TYPE, ui8);
		break;

	case IPPROTO_ESP:
		buf_cur += sprintf(buf_cur, "PROTO=ESP ");
		break;

	case IPPROTO_AH:
		buf_cur += sprintf(buf_cur, "PROTO=AH ");
		break;

	default:
		pp_print(buf_cur, "PROTO", res, PRINTFLOW_ORIG_IP_PROTOCOL, ui8);
		break;
	}

orig_out:
	pp_print(buf_cur, "PKTS", res, PRINTFLOW_ORIG_RAW_PKTCOUNT, ui32);
	pp_print(buf_cur, "BYTES", res, PRINTFLOW_ORIG_RAW_PKTLEN, ui32);

	buf_cur += sprintf(buf_cur, ", REPLY: ");

	if (pp_is_valid(res, PRINTFLOW_REPLY_IP_SADDR))
		buf_cur += sprintf(buf_cur, "SRC=%s ", inet_ntoa(
				(struct in_addr) {htonl(GET_VALUE(res, PRINTFLOW_REPLY_IP_SADDR).ui32)}));

	if (pp_is_valid(res, PRINTFLOW_REPLY_IP_DADDR))
		buf_cur += sprintf(buf_cur, "DST=%s ", inet_ntoa(
				(struct in_addr) {htonl(GET_VALUE(res, PRINTFLOW_REPLY_IP_DADDR).ui32)}));

	if (!pp_is_valid(res, PRINTFLOW_REPLY_IP_PROTOCOL))
		goto reply_out;

	switch (GET_VALUE(res, PRINTFLOW_REPLY_IP_PROTOCOL).ui8) {
	case IPPROTO_TCP:
		buf_cur += sprintf(buf_cur, "PROTO=TCP ");
		pp_print(buf_cur, "SPT", res, PRINTFLOW_REPLY_L4_SPORT, ui16);
		pp_print(buf_cur, "DPT", res, PRINTFLOW_REPLY_L4_DPORT, ui16);
		break;

	case IPPROTO_UDP:
		buf_cur += sprintf(buf_cur, "PROTO=UDP ");
		pp_print(buf_cur, "SPT", res, PRINTFLOW_REPLY_L4_SPORT, ui16);
		pp_print(buf_cur, "DPT", res, PRINTFLOW_REPLY_L4_DPORT, ui16);
		break;

	case IPPROTO_ICMP:
		buf_cur += sprintf(buf_cur, "PROTO=ICMP ");
		pp_print(buf_cur, "TYPE", res, PRINTFLOW_ICMP_CODE, ui8);
		pp_print(buf_cur, "CODE", res, PRINTFLOW_ICMP_TYPE, ui8);
		break;

	case IPPROTO_ESP:
		buf_cur += sprintf(buf_cur, "PROTO=ESP ");
		break;

	case IPPROTO_AH:
		buf_cur += sprintf(buf_cur, "PROTO=AH ");
		break;

	default:
		pp_print(buf_cur, "PROTO", res, PRINTFLOW_REPLY_IP_PROTOCOL, ui8);
		break;
	}

reply_out:
	pp_print(buf_cur, "PKTS", res, PRINTFLOW_REPLY_RAW_PKTCOUNT, ui32);
	pp_print(buf_cur, "BYTES", res, PRINTFLOW_REPLY_RAW_PKTLEN, ui32);

	strcat(buf_cur, "\n");
	return 0;
}
