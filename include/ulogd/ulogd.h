#ifndef _ULOGD_H
#define _ULOGD_H
/* ulogd, Version $Revision: 1.1 $
 *
 * first try of a logging daemon for my netfilter ULOG target
 * for the linux 2.4 netfilter subsystem.
 *
 * (C) 2000 by Harald Welte <laforge@sunbeam.franken.de>
 *
 * this code is released under the terms of GNU GPL
 *
 * $Id: ulog_test.c,v 1.1 2000/07/30 19:34:05 laforge Exp laforge $
 */

#include <libipulog/libipulog.h>

/* types without length */
#define ULOGD_RET_NONE		0x0000

#define ULOGD_RET_INT8		0x0001
#define ULOGD_RET_INT16		0x0002
#define ULOGD_RET_INT32		0x0003
#define ULOGD_RET_INT64		0x0004

#define ULOGD_RET_UINT8		0x0011
#define ULOGD_RET_UINT16	0x0012
#define ULOGD_RET_UINT32	0x0013
#define ULOGD_RET_UINT64	0x0014

#define ULOGD_RET_STRING	0x0020

#define ULOGD_RET_IPADDR	0x0100

/* types with lenght field*/
#define ULOGD_RET_OTHER		0xffff

#define ULOGD_MAX_KEYLEN 32

typedef struct ulog_iret {
	struct ulog_iret *next;
	u_int32_t len;
	u_int16_t type;
	char key[ULOGD_MAX_KEYLEN];
	void *value;
} ulog_iret_t;

typedef struct ulog_interpreter {
	struct ulog_interpreter *next;
	char name[ULOGD_MAX_KEYLEN];
	ulog_iret_t* (*interp)(ulog_packet_msg_t *pkt);
} ulog_interpreter_t;

void register_interpreter(ulog_interpreter_t *me);
ulog_iret_t *alloc_ret(const u_int16_t type, const char*);
#endif
