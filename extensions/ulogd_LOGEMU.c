/* ulogd_LOGEMU.c, Version $Revision: 1.7 $
 *
 * ulogd output target for syslog logging emulation
 *
 * This target produces a file which looks the same like the syslog-entries
 * of the LOG target.
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
 *
 * $Id: ulogd_LOGEMU.c,v 1.7 2001/09/01 11:51:54 laforge Exp $
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include "ulogd.h"
#include "conffile.h"

#ifndef ULOGD_LOGEMU_DEFAULT
#define ULOGD_LOGEMU_DEFAULT	"/var/log/ulogd.syslogemu"
#endif

#ifndef ULOGD_LOGEMU_SYNC_DEFAULT
#define ULOGD_LOGEMU_SYNC_DEFAULT	0
#endif

#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[3]

static config_entry_t syslogf_ce = { NULL, "syslogfile", CONFIG_TYPE_STRING, 
				  CONFIG_OPT_NONE, 0,
				  { string: ULOGD_LOGEMU_DEFAULT } };

static config_entry_t syslsync_ce = { &syslogf_ce, "syslogsync", 
				      CONFIG_TYPE_INT, CONFIG_OPT_NONE, 0,
				      { value: ULOGD_LOGEMU_SYNC_DEFAULT }
				     };

static FILE *of = NULL;

static char hostname[255];

struct intr_id {
	char* name;
	unsigned int id;		
};

#define INTR_IDS 	34
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
	{ "ahesp.spi", 0 },
};

#define GET_VALUE(x)	ulogd_keyh[intr_ids[x].id].interp->result[ulogd_keyh[intr_ids[x].id].offset].value
#define GET_FLAGS(x)	ulogd_keyh[intr_ids[x].id].interp->result[ulogd_keyh[intr_ids[x].id].offset].flags

int _output_logemu(ulog_iret_t *res)
{
	char *timestr;
	char *tmp;
	time_t now;

	/* get time */
	time(&now);
	timestr = ctime(&now) + 4;

	/* truncate time */
	if (tmp = strchr(timestr, '\n'))
		*tmp = '\0';

	/* truncate hostname */
	if (tmp = strchr(hostname, '.'))
		*tmp = '\0';

	/* print time and hostname */
	fprintf(of, "%.15s %s", timestr, hostname);

	if (*(char *) GET_VALUE(0).ptr)
		fprintf(of, " %s", (char *) GET_VALUE(0).ptr);

	fprintf(of," IN=%s OUT=%s ", 
		(char *) GET_VALUE(1).ptr, 
		(char *) GET_VALUE(2).ptr);

	/* FIXME: configurable */
	fprintf(of, "MAC=%s ",
		(GET_FLAGS(3) & ULOGD_RETF_VALID) ? (char *) GET_VALUE(3).ptr : "");

	fprintf(of, "SRC=%s ", inet_ntoa(htonl(GET_VALUE(4).ui32)));
	fprintf(of, "DST=%s ", inet_ntoa(htonl(GET_VALUE(5).ui32)));

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
					fprintf(of, "GATEWAY=%s ", inet_ntoa(htonl(GET_VALUE(31).ui32)));
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

	if (syslsync_ce.u.value) 
		fflush(of);

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
			ulogd_log(ULOGD_ERROR, 
				"Cannot resolve keyhash id for %s\n", 
				cur_id->name);
			return 1;
		}
	}	
	return 0;
}

void sighup_handler_logemu(int signal)
{
	switch (signal) {
	case SIGHUP:
		ulogd_log(ULOGD_NOTICE, "syslogemu: reopening logfile\n");
		fclose(of);
		of = fopen(syslogf_ce.u.string, "a");
		if (!of) {
			ulogd_log(ULOGD_FATAL, "can't open syslogemu: %s\n",
				strerror(errno));
			exit(2);
		}
		break;
	default:
		break;
	}
}
		

static ulog_output_t logemu_op[] = {
	{ NULL, "syslogemu", &_output_logemu, &sighup_handler_logemu },
	{ NULL, "", NULL, NULL },
};

/* register output plugin with ulogd */
static void _logemu_reg_op(void)
{
	ulog_output_t *op = logemu_op;
	ulog_output_t *p;

	for (p = op; p->output; p++)
		register_output(p);
}

void _init(void)
{
	/* FIXME: error handling */
	config_register_key(&syslsync_ce);
	config_parse_file(0);

	if (gethostname(hostname, sizeof(hostname)) < 0) {
		ulogd_log(ULOGD_FATAL, "can't gethostname(): %s\n",
			  strerror(errno));
		exit(2);
	}

#ifdef DEBUG_LOGEMU
	of = stdout;
#else
	of = fopen(syslogf_ce.u.string, "a");
	if (!of) {
		ulogd_log(ULOGD_FATAL, "can't open syslogemu: %s\n", 
			strerror(errno));
		exit(2);
	}		
#endif
	if (get_ids()) {
		ulogd_log(ULOGD_ERROR, "can't resolve all keyhash id's\n");
	}

	_logemu_reg_op();
}
