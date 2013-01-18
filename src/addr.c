/* IP address handling functions
 *
 * (C) 2012 by Pablo Neira Ayuso <pablo@netfilter.org>
 * (C) 2012 by Eric Leblond <eric@regit.org>
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
 */

#include <arpa/inet.h>

#include <ulogd/ulogd.h>
#include <ulogd/addr.h>

u_int32_t ulogd_bits2netmask(int bits)
{
	u_int32_t netmask, bm;

	if (bits >= 32 || bits < 0)
		return(~0);
	for (netmask = 0, bm = 0x80000000; bits; bits--, bm >>= 1)
		netmask |= bm;
	return netmask;
}


void ulogd_ipv6_cidr2mask_host(uint8_t cidr, uint32_t *res)
{
	int i, j;

	memset(res, 0, sizeof(uint32_t)*4);
	for (i = 0;  i < 4 && cidr > 32; i++) {
		res[i] = 0xFFFFFFFF;
		cidr -= 32;
	}
	res[i] = 0xFFFFFFFF << (32 - cidr);
	for (j = i+1; j < 4; j++) {
		res[j] = 0;
	}
}

/* I need this function because I initially defined an IPv6 address as
 * uint32 u[4]. Using char u[16] instead would allow to remove this. */
void ulogd_ipv6_addr2addr_host(uint32_t *addr, uint32_t *res)
{
	int i;

	memset(res, 0, sizeof(uint32_t)*4);
	for (i = 0;  i < 4; i++) {
		res[i] = ntohl(addr[i]);
	}
}

int ulogd_parse_addr(char *string, size_t len, struct ulogd_addr *addr)
{
	char filter_addr[128];
	char *slash;
	char *ddash;
	if ((ddash = strchr(string, ':')) && (ddash < string + len)) {
		struct in6_addr raddr;
		int i;
		slash = strchr(string, '/');
		if (slash == NULL) {
			ulogd_log(ULOGD_FATAL,
					"No network specified\n");
			return -1;
		}

		strncpy(filter_addr, string,
				slash - string);
		filter_addr[slash - string] = 0;
		if (inet_pton(AF_INET6, filter_addr, (void *)&raddr)
				!= 1) {
			ulogd_log(ULOGD_FATAL,
					"error reading address\n");
			return -1;
		}
		for(i = 0; i < 4; i++)
			addr->in.ipv6[i] = raddr.s6_addr32[i];
		addr->netmask = atoi(slash + 1);

		return AF_INET6;
	}
	if ((ddash = strchr(string, '.')) && (ddash < string + len)) {
		slash = strchr(string, '/');
		if (slash == NULL) {
			ulogd_log(ULOGD_FATAL,
					"No network specified\n");
			return -1;
		}
		strncpy(filter_addr, string,
				slash - string);
		filter_addr[slash - string] = 0;
		addr->in.ipv4 = inet_addr(filter_addr);
		addr->netmask = atoi(slash + 1);

		return AF_INET;
	}
	return -1;
}
