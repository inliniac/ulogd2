/* ulogd_LOGEMU.c, Version $Revision: 1.4 $
 *
 * ulogd output target for syslog logging emulation
 * this target produces a file which looks the same like the syslog-entries
 * of the LOG target.
 *
 * (C) 2000 by Harald Welte <laforge@gnumonks.org>
 * This software is released under the terms of GNU GPL
 *
 * $Id: ulogd_LOGEMU.c,v 1.4 2000/09/22 06:54:33 laforge Exp $
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include "ulogd.h"
#include "conffile.h"

#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[3]

#define HIPQUAD(addr) \
        ((unsigned char *)&addr)[3], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[0]

static FILE *of = NULL;

struct intr_id {
	char* name;
	unsigned int id;		
};

#define INTR_IDS 	33
static struct intr_id intr_ids[INTR_IDS] = {
	{ "oob.prefix", 0 },
	{ "oob.in", 0 },
	{ "oob.out", 0 },
	{ "raw.mac", 0 },
	{ "ip.saddr", 0 },
	{ "ip.daddr", 0 },
	{ "ip.totlen", 0 },
	{ "ip.tos", 0 },
	{ "ip.ttl", 0 },
	{ "ip.id", 0 },
	{ "ip.fragoff", 0 },
	{ "ip.protocol", 0 },
	{ "tcp.sport", 0 },
	{ "tcp.dport", 0 },
	{ "tcp.seq", 0 },
	{ "tcp.ackseq", 0 },
	{ "tcp.window", 0 },
	{ "tcp.urg", 0 },
	{ "tcp.ack", 0 },
	{ "tcp.psh", 0 },
	{ "tcp.rst", 0 },
	{ "tcp.syn", 0 },
	{ "tcp.fin", 0 },
	{ "tcp.urgp", 0 },
	{ "udp.sport", 0 },
	{ "udp.dport", 0 },
	{ "udp.len", 0 },
	{ "icmp.type", 0 },
	{ "icmp.code", 0 },
	{ "icmp.echoid", 0 },
	{ "icmp.echoseq", 0 },
	{ "icmp.gateway", 0 },
	{ "icmp.fragmtu", 0 },
	{ "ah.spi", 0 },
};

#define GET_VALUE(x)	ulogd_keyh[intr_ids[x].id].interp->result[ulogd_keyh[intr_ids[x].id].offset].value
#define IS_VALID(x)	(ulogd_keyh[intr_ids[x].id].interp->result[ulogd_keyh[intr_ids[x].id].offset].flags & ULOGD_RETF_VALID)

int _output_logemu(ulog_iret_t *res)
{
	fprintf(of, "%sIN=%s OUT=%s ", 
		(char *) GET_VALUE(0).ptr, 
		(char *) GET_VALUE(1).ptr, 
		(char *) GET_VALUE(2).ptr);

	/* FIXME: configurable */
	fprintf(of, "MAC=%s ", (char *) GET_VALUE(3).ptr);

	fprintf(of, "SRC=%u.%u.%u.%u DST=%u.%u.%u.%u ", 
			HIPQUAD(GET_VALUE(4).ui32), HIPQUAD(GET_VALUE(5).ui32));

	fprintf(of, "LEN=%u TOS=%02X PREC=0x%02X TTL=%u ID=%u ", 
			GET_VALUE(6).ui16, GET_VALUE(7).ui8 & IPTOS_TOS_MASK, 
			GET_VALUE(7).ui8 & IPTOS_PREC_MASK, GET_VALUE(8).ui8,
			GET_VALUE(9).ui16);

	if (GET_VALUE(10).ui16 & IP_RF) 
		fprintf(of, "CE ");

	if (GET_VALUE(10).ui16 & IP_DF)
		fprintf(of, "DF ");

	if (GET_VALUE(10).ui16 & IP_MF)
		fprintf(of, "MF ");

	if (GET_VALUE(10).ui16 & IP_OFFMASK)
		fprintf(of, "FRAG:%u ", GET_VALUE(10).ui16 & IP_OFFMASK);

	switch (GET_VALUE(11).ui8) {

		case IPPROTO_TCP:
			fprintf(of, "PROTO=TCP ");
			fprintf(of, "SPT=%u DPT=%u ", GET_VALUE(12).ui16,
				GET_VALUE(13).ui16);
			/* FIXME: config */
			fprintf(of, "SEQ=%u ACK=%u ", GET_VALUE(14).ui32,
				GET_VALUE(15).ui32);

			fprintf(of, "WINDOW=%u ", GET_VALUE(16).ui16);

//			fprintf(of, "RES=0x%02x ", 
		
			if (GET_VALUE(17).b)
				fprintf(of, "URG ");

			if (GET_VALUE(18).b)
				fprintf(of, "ACK ");

			if (GET_VALUE(19).b)
				fprintf(of, "PSH ");

			if (GET_VALUE(20).b)
				fprintf(of, "RST ");

			if (GET_VALUE(21).b)
				fprintf(of, "SYN ");

			if (GET_VALUE(22).b)
				fprintf(of, "FIN ");

			fprintf(of, "URGP=%u ", GET_VALUE(23).ui16);

			break;
		case IPPROTO_UDP:

			fprintf(of, "PROTO=UDP ");

			fprintf(of, "SPT=%u DPT=%u LEN=%u ", 
				GET_VALUE(24).ui16, GET_VALUE(25).ui16, 
				GET_VALUE(26).ui16);
			break;
		case IPPROTO_ICMP:

			fprintf(of, "PROTO=ICMP ");

			fprintf(of, "TYPE=%u CODE=%u ", GET_VALUE(27).ui8,
				GET_VALUE(28).ui8);

			switch (GET_VALUE(27).ui8) {
				case ICMP_ECHO:
				case ICMP_ECHOREPLY:
					fprintf(of, "ID=%u SEQ=%u ", 
						GET_VALUE(29).ui16,
						GET_VALUE(30).ui16);
					break;
				case ICMP_PARAMETERPROB:
					fprintf(of, "PARAMETER=%u ",
						GET_VALUE(31).ui32 >> 24);
					break;
				case ICMP_REDIRECT:
					fprintf(of, "GATEWAY=%u.%u.%u.%u ",
						HIPQUAD(GET_VALUE(31).ui32));
					break;
				case ICMP_DEST_UNREACH:
					if (GET_VALUE(28).ui8 == ICMP_FRAG_NEEDED)
						fprintf(of, "MTU=%u ", 
							GET_VALUE(32).ui16);
					break;
			}
			break;
	}
	fprintf(of,"\n");
	return 0;
}
/* get all key id's for the keys we are intrested in */
static int get_ids(void)
{
	int i;
	struct intr_id *cur_id;

	for (i = 0; i < INTR_IDS; i++) {
		cur_id = &intr_ids[i];
		cur_id->id = keyh_getid(cur_id->name);
		if (!cur_id->id) {
			ulogd_error("Cannot resolve keyhash id for %s\n", cur_id->name);
			return 1;
		}
	}	
	return 0;
}

static ulog_output_t logemu_op[] = {
	{ NULL, "logemu", &_output_logemu },
	{ NULL, "", NULL },
};

/* register output plugin with ulogd */
static void _logemu_reg_op(void)
{
	ulog_output_t *op = logemu_op;
	ulog_output_t *p;

	for (p = op; p->output; p++)
		register_output(p);
}

static config_entry_t syslogf_ce = { NULL, "syslogfile", CONFIG_TYPE_STRING, 
				  CONFIG_OPT_NONE, 0,
				  { string: "/var/log/ulogd.syslogemu" } };
void _init(void)
{
#ifdef DEBUG_LOGEMU
	of = stdout;
#else
	config_register_key(&syslogf_ce);
	config_parse_file(0);

	of = fopen(syslogf_ce.u.string, "a");
	if (!of) {
		ulogd_error("ulogd_LOGEMU: can't open syslogemu: %s\n", strerror(errno));
		exit(2);
	}		
#endif
	if (get_ids()) {
		ulogd_error("ulogd_LOGEMU: can't resolve all keyhash id's\n");
		exit(2);
	}

	_logemu_reg_op();
}
