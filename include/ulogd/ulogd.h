#ifndef _ULOGD_H
#define _ULOGD_H
/* ulogd, Version $Revision: 1.6 $
 *
 * first try of a logging daemon for my netfilter ULOG target
 * for the linux 2.4 netfilter subsystem.
 *
 * (C) 2000 by Harald Welte <laforge@sunbeam.franken.de>
 *
 * this code is released under the terms of GNU GPL
 *
 * $Id: ulogd.h,v 1.6 2000/09/12 13:43:34 laforge Exp $
 */

#include <libipulog/libipulog.h>

/* All types with MSB = 1 make use of value.ptr
 * other types use one of the union's member */

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

#define ULOGD_RET_BOOL		0x0050

#define ULOGD_RET_IPADDR	0x0100

/* types with lenght field*/
#define ULOGD_RET_STRING	0x8020
#define ULODG_RET_RAW		0x8030

#define ULOGD_RET_OTHER		0xffff

/* maximum length of ulogd key */
#define ULOGD_MAX_KEYLEN 32

#define ULOGD_DEBUG	1
#define ULOGD_NOTICE	5
#define ULOGD_ERROR	8


extern FILE *logfile;

typedef struct ulog_iret {
	struct ulog_iret *next;
	u_int32_t len;
	u_int16_t type;
	char key[ULOGD_MAX_KEYLEN];
	union {
		u_int8_t	b;
		u_int8_t	ui8;
		u_int16_t	ui16;
		u_int32_t	ui32;
		u_int64_t	ui64;
		int8_t		i8;
		int16_t		i16;
		int32_t		i32;
		int64_t		i64;
		void		*ptr;
	} value;
} ulog_iret_t;

typedef struct ulog_interpreter {
	struct ulog_interpreter *next;
	char name[ULOGD_MAX_KEYLEN];
	ulog_iret_t* (*interp)(ulog_packet_msg_t *pkt);
} ulog_interpreter_t;

typedef struct ulog_output {
	struct ulog_output *next;
	char name[ULOGD_MAX_KEYLEN];
	int* (*output)(ulog_iret_t *ret);
} ulog_output_t;

/***********************************************************************
 * PUBLIC INTERFACE 
 ***********************************************************************/

/* register a new interpreter plugin */
void register_interpreter(ulog_interpreter_t *me);

/* register a new output target */
void register_output(ulog_output_t *me);

/* allocate a new ulog_iret_t */
ulog_iret_t *alloc_ret(const u_int16_t type, const char*);

/* write a message to the daemons' logfile */
void ulogd_log(int level, const char *message, ...);

/* backwards compatibility */
#define ulogd_error(format, args...) ulogd_log(ULOGD_ERROR, format, ## args)

#endif
