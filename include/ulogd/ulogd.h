#ifndef _ULOGD_H
#define _ULOGD_H
/* ulogd, Version $Revision$
 *
 * userspace logging daemon for netfilter ULOG target
 * of the linux 2.4/2.6 netfilter subsystem.
 *
 * (C) 2000-2005 by Harald Welte <laforge@gnumonks.org>
 *
 * this code is released under the terms of GNU GPL
 *
 * $Id$
 */

#include <ulogd/linuxlist.h>
#include <ulogd/conffile.h>
#include <ulogd/ipfix_protocol.h>
#include <stdio.h>
#include <signal.h>	/* need this because of extension-sighandler */
#include <sys/types.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))


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

/* types with length field */
#define ULOGD_RET_STRING	0x8020
#define ULOGD_RET_RAW		0x8030


/* FLAGS */
#define ULOGD_RETF_NONE		0x0000
#define ULOGD_RETF_VALID	0x0001	/* contains a valid result */
#define ULOGD_RETF_FREE		0x0002	/* ptr needs to be free()d */
#define ULOGD_RETF_NEEDED	0x0004	/* this parameter is actually needed
					 * by some downstream plugin */

#define ULOGD_KEYF_OPTIONAL	0x0100	/* this key is optional */
#define ULOGD_KEYF_INACTIVE	0x0200	/* marked as inactive (i.e. totally
					   to be ignored by everyone */


/* maximum length of ulogd key */
#define ULOGD_MAX_KEYLEN 31

#define ULOGD_DEBUG	1	/* debugging information */
#define ULOGD_INFO	3
#define ULOGD_NOTICE	5	/* abnormal/unexpected condition */
#define ULOGD_ERROR	7	/* error condition, requires user action */
#define ULOGD_FATAL	8	/* fatal, program aborted */

/* ulogd data type */
enum ulogd_dtype {
	ULOGD_DTYPE_NULL,
	ULOGD_DTYPE_SOURCE,	/* source of data, no input keys */
	ULOGD_DTYPE_RAW,	/* raw packet data */
	ULOGD_DTYPE_PACKET,	/* packet metadata */
	ULOGD_DTYPE_FLOW,	/* flow metadata */
	ULOGD_DTYPE_SINK,	/* sink of data, no output keys */
};

/* structure describing an input  / output parameter of a plugin */
struct ulogd_key {
	/* length of the returned value (only for lengthed types */
	u_int32_t len;
	/* type of the returned value (ULOGD_DTYPE_...) */
	u_int16_t type;
	/* flags (i.e. free, ...) */
	u_int16_t flags;
	/* name of this key */
	char name[ULOGD_MAX_KEYLEN+1];
	/* IETF IPFIX attribute ID */
	struct {
		u_int32_t	vendor;
		u_int16_t	field_id;
	} ipfix;

	union {
		/* and finally the returned value */
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
		struct ulogd_key *source;
	} u;
};

struct ulogd_pluginstance_stack;
struct ulogd_pluginstance;
struct ulogd_plugin {
	/* global list of plugins */
	struct list_head list;
	/* name of this plugin (predefined by plugin) */
	char name[ULOGD_MAX_KEYLEN];
	/* ID for this plugin (dynamically assigned) */
	unsigned int id;
	struct {
		/* possible input keys of this interpreter */
		struct ulogd_key *keys;
		/* number of input keys */
		unsigned int num_keys;
		/* type */
		enum ulogd_dtype type;
	} input;
	struct {
		/* possible input keys of this interpreter */
		struct ulogd_key *keys;
		/* number of keys this interpreter has */
		unsigned int num_keys;
		/* type */
		enum ulogd_dtype type;
	} output;

	/* function to call for each packet */
	int (*interp)(struct ulogd_pluginstance *instance);

	int (*configure)(struct ulogd_pluginstance *instance,
			 struct ulogd_pluginstance_stack *stack);

	/* function to construct a new pluginstance */
	int (*start)(struct ulogd_pluginstance *pi);
	/* function to destruct an existing pluginstance */
	int (*stop)(struct ulogd_pluginstance *pi);

	/* function to receive a signal */
	void (*signal)(struct ulogd_pluginstance *pi, int signal);

	/* configuration parameters */
	struct config_keyset *config_kset;

	/* size of instance->priv */
	unsigned int priv_size;
};

#define ULOGD_IRET_ERR		-1
#define ULOGD_IRET_STOP		-2
#define ULOGD_IRET_OK		0

/* an instance of a plugin, element in a stack */
struct ulogd_pluginstance {
	/* local list of plugins in this stack */
	struct list_head list;
	/* plugin */
	struct ulogd_plugin *plugin;
	/* stack that we're part of */
	struct ulogd_pluginstance_stack *stack;
	/* name / id  of this instance*/
	char id[ULOGD_MAX_KEYLEN];
	/* per-instance input keys */
	struct ulogd_key *input;
	/* per-instance output keys */
	struct ulogd_key *output;
	/* per-instance config parameters (array) */
	struct config_keyset *config_kset;
	/* private data */
	char private[0];
};

struct ulogd_pluginstance_stack {
	/* global list of pluginstance stacks */
	struct list_head stack_list;
	/* list of plugins in this stack */
	struct list_head list;
	char *name;
};

/***********************************************************************
 * PUBLIC INTERFACE 
 ***********************************************************************/

void ulogd_propagate_results(struct ulogd_pluginstance *pi);

/* register a new interpreter plugin */
void ulogd_register_plugin(struct ulogd_plugin *me);

/* allocate a new ulogd_key */
struct ulogd_key *alloc_ret(const u_int16_t type, const char*);

/* write a message to the daemons' logfile */
void __ulogd_log(int level, char *file, int line, const char *message, ...);
/* macro for logging including filename and line number */
#define ulogd_log(level, format, args...) \
	__ulogd_log(level, __FILE__, __LINE__, format, ## args)
/* backwards compatibility */
#define ulogd_error(format, args...) ulogd_log(ULOGD_ERROR, format, ## args)

/* get an interpreter hash id by name */
unsigned int interh_getid(const char *name);

/* get a key id if you have the name */
unsigned int keyh_getid(const char *name);

/* get a result for a given key id */
struct ulogd_key *keyh_getres(unsigned int id);

/* the key hash itself */
extern struct ulogd_keyh_entry *ulogd_keyh;

#define IS_VALID(x)	(x.flags & ULOGD_RETF_VALID)
#define SET_VALID(x)	(x.flags |= ULOGD_RETF_VALID)
#define IS_NEEDED(x)	(x.flags & ULOGD_RETF_NEEDED)
#define SET_NEEDED(x)	(x.flags |= ULOGD_RETF_NEEDED)

/***********************************************************************
 * file descriptor handling
 ***********************************************************************/

#define ULOGD_FD_READ	0x0001
#define ULOGD_FD_WRITE	0x0002
#define ULOGD_FD_EXCEPT	0x0004

struct ulogd_fd {
	struct list_head list;
	int fd;				/* file descriptor */
	unsigned int when;
	int (*cb)(int fd, unsigned int what, void *data);
	void *data;			/* void * to pass to callback */
};

int ulogd_register_fd(struct ulogd_fd *ufd);
void ulogd_unregister_fd(struct ulogd_fd *ufd);

#endif /* _ULOGD_H */
