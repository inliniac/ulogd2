/* ulogd_PWSNIFF.c, Version $Revision: 1.1 $
 *
 * ulogd logging interpreter for POP3 / FTP like plaintext passwords.
 *
 * (C) 2000 by Harald Welte <laforge@gnumonks.org>
 * This software is released under the terms of GNU GPL
 *
 * $Id: ulogd_PWSNIFF.c,v 1.1 2000/08/17 08:03:22 laforge Exp $
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <ulogd.h>
#include <string.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>

#ifdef DEBUG
#define DEBUGP ulogd_error
#else
#define DEBUGP(format, args...)
#endif


#define PORT_POP3	110
#define PORT_FTP	21

static u_int16_t pwsniff_ports[] = {
	__constant_htons(PORT_POP3),
	__constant_htons(PORT_FTP),
};

#define PWSNIFF_MAX_PORTS 2

static char *_get_next_blank(char* begp, char *endp)
{
	char *ptr;

	for (ptr = begp; ptr < endp; ptr++) {
		if (*ptr == ' ' || *ptr == '\n' || *ptr == '\r') {
			return ptr-1;	
		}
	}
	return NULL;
}

static ulog_iret_t *_interp_pwsniff(ulog_packet_msg_t *pkt)
{
	struct iphdr *iph = (struct iphdr *) pkt->payload;
	void *protoh = (u_int32_t *)iph + iph->ihl;
	struct tcphdr *tcph = protoh;
	u_int32_t tcplen = ntohs(iph->tot_len) - iph->ihl * 4;
	unsigned char  *ptr, *begp, *pw_begp, *endp, *pw_endp;
	ulog_iret_t *ret = NULL;
	ulog_iret_t *ret2;
	int len, pw_len, i, cont = 0;

	len = pw_len = 0;
	begp = pw_begp = NULL;

	if (iph->protocol != IPPROTO_TCP)
		return NULL;
	
	for (i = 0; i <= PWSNIFF_MAX_PORTS; i++)
	{
		if (tcph->dest == pwsniff_ports[i]) {
			cont = 1; 
			break;
		}
	}
	if (!cont)
		return NULL;

	DEBUGP("----> pwsniff detected, tcplen=%d, struct=%d, iphtotlen=%d, ihl=%d\n", tcplen, sizeof(struct tcphdr), ntohs(iph->tot_len), iph->ihl);

	for (ptr = (unsigned char *) tcph + sizeof(struct tcphdr); 
			ptr < (unsigned char *) tcph + tcplen; ptr++)
	{
		if (!strncasecmp(ptr, "USER ", 5)) {
			begp = ptr+5;
			endp = _get_next_blank(begp, (char *)tcph + tcplen);
			if (endp)
				len = endp - begp + 1;
		}
		if (!strncasecmp(ptr, "PASS ", 5)) {
			pw_begp = ptr+5;
			pw_endp = _get_next_blank(pw_begp, 
					(char *)tcph + tcplen);
			if (pw_endp)
				pw_len = pw_endp - pw_begp + 1;
		}
	}

	if (len) {
		ret = alloc_ret(ULOGD_RET_STRING, "pwsniff.user");
		ret->value.ptr = (char *) malloc(len+1);
		if (!ret->value.ptr) {
			ulogd_error("_interp_pwsniff: OOM (size=%u)\n", len);
			free(ret);
			return NULL;
		}
		strncpy(ret->value.ptr, begp, len);
		*((char *)ret->value.ptr + len + 1) = '\0';
	}
	if (pw_len) {
		ret2 = alloc_ret(ULOGD_RET_STRING,"pwsniff.pass");
		ret2->value.ptr = (char *) malloc(pw_len+1);
		if (!ret2->value.ptr){
			ulogd_error("_interp_pwsniff: OOM (size=%u)\n", pw_len);
			free(ret2);
			return NULL;
		}
		strncpy(ret2->value.ptr, pw_begp, pw_len);
		*((char *)ret2->value.ptr + pw_len + 1) = '\0';

		if (ret) 
			ret->next = ret2;
		else
			ret = ret2;
	}
	return ret;
}
static ulog_interpreter_t base_ip[] = { 

	{ NULL, "pwsniff", &_interp_pwsniff },
	{ NULL, "", NULL }, 
};
void _base_reg_ip(void)
{
	ulog_interpreter_t *ip = base_ip;
	ulog_interpreter_t *p;

	for (p = ip; p->interp; p++)
		register_interpreter(p);

}


void _init(void)
{
	_base_reg_ip();
}
