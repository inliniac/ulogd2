/* ulogd_MAC.c, Version $Revision: 1.9 $
 *
 * ulogd output target for logging to a file 
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
 * $Id: ulogd_OPRINT.c,v 1.9 2002/12/09 14:42:43 laforge Exp $
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ulogd/ulogd.h>
#include <ulogd/conffile.h>

#ifndef ULOGD_OPRINT_DEFAULT
#define ULOGD_OPRINT_DEFAULT	"/var/log/ulogd.pktlog"
#endif

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

int _output_print(ulog_iret_t *res)
{
	ulog_iret_t *ret;
	
	fprintf(of, "===>PACKET BOUNDARY\n");
	for (ret = res; ret; ret = ret->cur_next) {
		fprintf(of,"%s=", ret->key);
		switch (ret->type) {
			case ULOGD_RET_STRING:
				fprintf(of, "%s\n", (char *) ret->value.ptr);
				break;
			case ULOGD_RET_BOOL:
			case ULOGD_RET_INT8:
			case ULOGD_RET_INT16:
			case ULOGD_RET_INT32:
				fprintf(of, "%d\n", ret->value.i32);
				break;
			case ULOGD_RET_UINT8:
			case ULOGD_RET_UINT16:
			case ULOGD_RET_UINT32:
				fprintf(of, "%u\n", ret->value.ui32);
				break;
			case ULOGD_RET_IPADDR:
				fprintf(of, "%u.%u.%u.%u\n", 
					HIPQUAD(ret->value.ui32));
				break;
			case ULOGD_RET_NONE:
				fprintf(of, "<none>");
				break;
		}
	}
	return 0;
}

static config_entry_t outf_ce = { NULL, "file", CONFIG_TYPE_STRING, 
				  CONFIG_OPT_NONE, 0,
				  { string: ULOGD_OPRINT_DEFAULT } };

void sighup_handler_print(int signal)
{

	switch (signal) {
	case SIGHUP:
		ulogd_log(ULOGD_NOTICE, "PKTLOG: reopening logfile\n");
		fclose(of);
		of = fopen(outf_ce.u.string, "a");
		if (!of) {
			ulogd_log(ULOGD_FATAL, "can't open PKTLOG: %s\n",
				strerror(errno));
			exit(2);
		}
		break;
	default:
		break;
	}
}

static ulog_output_t base_op[] = {
	{ NULL, "oprint", &_output_print, &sighup_handler_print },
	{ NULL, "", NULL, NULL },
};


static void _base_reg_op(void)
{
	ulog_output_t *op = base_op;
	ulog_output_t *p;

	for (p = op; p->output; p++)
		register_output(p);
}

void _init(void)
{
#ifdef DEBUG
	of = stdout;
#else
	config_parse_file("OPRINT", &outf_ce);

	of = fopen(outf_ce.u.string, "a");
	if (!of) {
		ulogd_log(ULOGD_FATAL, "can't open PKTLOG: %s\n", 
			strerror(errno));
		exit(2);
	}		
#endif
		
	_base_reg_op();
}
