/* ulogd_MAC.c, Version $Revision: 1.1 $
 *
 * ulogd output target for logging to a file 
 *
 * (C) 2000 by Harald Welte <laforge@sunbeam.franken.de>
 * This software is released under the terms of GNU GPL
 *
 * $Id: ulogd_OPRINT.c,v 1.1 2000/08/02 08:51:15 laforge Exp laforge $
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ulogd.h>

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

#define ULOGD_OPRINT_FILE	"/var/log/ulogd.pktlog"

static FILE *of = NULL;

int _output_print(ulog_iret_t *res)
{
	ulog_iret_t *ret;
	
	fprintf(of, "===>PACKET BOUNDARY\n");
	for (ret = res; ret; ret = ret->next)
	{
		fprintf(of,"%s=", ret->key);
		switch (ret->type) {
			case ULOGD_RET_STRING:
				fprintf(of, "%s\n", (char *) ret->value.ptr);
				break;
			case ULOGD_RET_INT8:
				fprintf(of, "%d\n", ret->value.i8);
				break;
			case ULOGD_RET_INT16:
				fprintf(of, "%d\n", ret->value.i16);
				break;
			case ULOGD_RET_INT32:
				fprintf(of, "%ld\n", ret->value.i32);
				break;
			case ULOGD_RET_UINT8:
				fprintf(of, "%u\n", ret->value.ui8);
				break;
			case ULOGD_RET_UINT16:
				fprintf(of, "%u\n", ret->value.ui16);
				break;
			case ULOGD_RET_UINT32:
				fprintf(of, "%lu\n", ret->value.ui32);
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

static ulog_output_t base_op[] = {
	{ NULL, "print.console", &_output_print },
	{ NULL, "", NULL },
};


void _base_reg_op(void)
{
	ulog_output_t *op = base_op;
	ulog_output_t *p;

	for (p = op; p->output; p++)
		register_output(p);
}

void _init(void)
{
	of = fopen(ULOGD_OPRINT_FILE, "a");
	if (!of) {
		ulogd_error("ulogd_OPRINT: can't open PKTLOG: %s\n", strerror(errno));
		exit(2);
	}		
		
	_base_reg_op();
}
