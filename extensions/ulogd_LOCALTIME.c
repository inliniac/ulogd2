/* ulogd_LOCALTIME.c, Version 0.2
 *
 * ulogd locatime logger for each and every packet we see ;)
 *
 * (C) 2001-2002 by Florent AIDE <faide@alphacent.com>
 *	with the help of Moez MKADMI <moez.mka@voila.fr>
 * shamelessly ripped from Harald Welte
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
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <ulogd.h>
#include <string.h>

#ifdef DEBUG_LOCALTIME
#define DEBUGP(x) ulogd_log(ULOGD_DEBUG, x)
#else
#define DEBUGP(format, args...)
#endif

static ulog_iret_t *_interp_localtime(ulog_interpreter_t *ip, 
				      ulog_packet_msg_t *pkt)
{
	struct timeval tv;
	ulog_iret_t *ret = ip->result;

	/* Get date */
	gettimeofday(&tv, NULL);

	/* put date */
	ret[0].value.ui32 = (unsigned long) tv.tv_sec; 
	ret[0].flags |= ULOGD_RETF_VALID;

	return ret;
}

static ulog_iret_t localtime_rets[] = {
	{ NULL, NULL, 0, ULOGD_RET_UINT32, ULOGD_RETF_NONE, "local.time", 
	  { ui32: 0 } },
};

static ulog_interpreter_t localtime_ip[] = { 

	{ NULL, "local", 0, &_interp_localtime, 1, &localtime_rets },
	{ NULL, "", 0, NULL, 0, NULL }, 
};

void _localtime_reg_ip(void)
{
	ulog_interpreter_t *ip = localtime_ip;
	ulog_interpreter_t *p;

	for (p = ip; p->interp; p++)
		register_interpreter(p);

}

void _init(void)
{
	_localtime_reg_ip();
}
