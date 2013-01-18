/* IP address handling functions
 *
 * (C) 2012 by Pablo Neira Ayuso <pablo@netfilter.org>
 * (C) 2012 by Eric Leblond <eric@regit.org>
 *
 * This code is distributed under the terms of GNU GPL version 2 */

#ifndef _ADDR_H
#define _ADDR_H

u_int32_t ulogd_bits2netmask(int bits);
void ulogd_ipv6_cidr2mask_host(uint8_t cidr, uint32_t *res);
void ulogd_ipv6_addr2addr_host(uint32_t *addr, uint32_t *res);

struct ulogd_addr {
	union {
		uint32_t ipv4;
		uint32_t ipv6[4];
	} in;
	uint32_t netmask;
};

int ulogd_parse_addr(char *string, size_t len, struct ulogd_addr *addr);

#endif
