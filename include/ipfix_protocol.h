#ifndef _IPFIX_PROTOCOL_H
#define _IPFIX_PROTOCOL_H

/* This header file defines structures for the IPFIX protocol in accordance with
 * draft-ietf-ipfix-protocol-03.txt */

#define IPFIX_VENDOR_NETFILTE	0x23424223

/* Section 8.1 */
struct ipfix_msg_hdr {
	u_int16_t	version;
	u_int16_t	length;
	u_int32_t	export_time;
	u_int32_t	seq;
	u_int32_t	source_id;
};

/* Section 8.2 */
struct ipfix_ietf_field {
	u_int16_t	type;
	u_int16_t	length;
};

struct ipfix_vendor_field {
	u_int16_t	type;
	u_int16_t	length;
	u_int32_t	enterprise_num;
};


#endif
