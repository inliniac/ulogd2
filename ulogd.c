/* ulogd, Version $Revision: 1.13 $
 *
 * userspace logging daemon for the netfilter ULOG target
 * of the linux 2.4 netfilter subsystem.
 *
 * (C) 2000 by Harald Welte <laforge@gnumonks.org>
 *
 * this code is released under the terms of GNU GPL
 *
 * $Id: ulogd.c,v 1.13 2000/11/20 11:43:22 laforge Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <dirent.h>
#include <libipulog/libipulog.h>
#include "conffile.h"
#include "ulogd.h"

/* Size of the netlink receive buffer. If you have _big_ in-kernel
 * queues, you may have to increase this number. 
 * ( --qthreshold 100 * 1500 bytes/packet = 150kB */
#define MYBUFSIZ 65535

#ifdef DEBUG
#define DEBUGP(format, args...) fprintf(stderr, format, ## args)
#else
#define DEBUGP(format, args...) 
#endif

/* default config parameters, if not changed in configfile */
#ifndef ULOGD_LOGFILE_DEFAULT
#define ULOGD_LOGFILE_DEFAULT	"/var/log/ulogd.log"
#endif
#ifndef ULOGD_NLGROUP_DEFAULT
#define ULOGD_NLGROUP_DEFAULT	32
#endif

/* where to look for the config file */
#ifndef ULOGD_CONFIGFILE
#define ULOGD_CONFIGFILE	"/etc/ulogd.conf"
#endif


FILE *logfile = NULL;
int loglevel = 1;

/* linked list for all registered interpreters */
static ulog_interpreter_t *ulogd_interpreters;

/* linked list for all registered output targets */
static ulog_output_t *ulogd_outputs;

/***********************************************************************
 * INTERPRETER AND KEY HASH FUNCTIONS 			(new in 0.9)
 ***********************************************************************/

/* We keep hashtables of interpreters and registered keys. The hash-tables
 * are allocated dynamically at program load time. You may control the
 * allocation granularity of both hashes (i.e. the amount of hashtable
 * entries are allocated at one time) through modification of the constants
 * INTERH_ALLOC_GRAN and KEYH_ALLOC_GRAN 
 */

/* allocation granularith */
#define INTERH_ALLOC_GRAN	5

/* hashtable for all registered interpreters */
static ulog_interpreter_t **ulogd_interh;

/* current hashtable size */
static unsigned int ulogd_interh_ids_alloc;

/* total number of registered ids */
static unsigned int ulogd_interh_ids;

/* allocate a new interpreter id and write it into the interpreter struct */
static unsigned int interh_allocid(ulog_interpreter_t *ip)
{
	unsigned int id;

	id = ++ulogd_interh_ids;
	
	if (id >= ulogd_interh_ids_alloc) {
		if (!ulogd_interh)
			ulogd_interh = (ulog_interpreter_t **) 
				malloc(INTERH_ALLOC_GRAN *
					sizeof(ulog_interpreter_t));
		else
			ulogd_interh = (ulog_interpreter_t **)
				realloc(ulogd_interh, 
					(INTERH_ALLOC_GRAN +
					 ulogd_interh_ids_alloc) *
					sizeof(ulog_interpreter_t));

		ulogd_interh_ids_alloc += INTERH_ALLOC_GRAN;
	}

	ip->id = id;
	ulogd_interh[id] = ip;
	return id;
}

/* get interpreter id by name */
unsigned int interh_getid(const char *name)
{
	int i;
	for (i = 1; i <= ulogd_interh_ids; i++)
		if (!strcmp(name, (ulogd_interh[i])->name))
			return i;

	return 0;
}

/* dump out the contents of the interpreter hash */
static void interh_dump(void)
{
	int i;

	for (i = 1; i <= ulogd_interh_ids; i++)
		ulogd_log(ULOGD_DEBUG, "ulogd_interh[%d] = %s\n", 
			i, (ulogd_interh[i])->name);

}

/* key hash allocation granularity */
#define KEYH_ALLOC_GRAN 20

/* hash table for key ids */
struct ulogd_keyh_entry *ulogd_keyh;

/* current size of the hashtable */
static unsigned int ulogd_keyh_ids_alloc;

/* total number of registered keys */
static unsigned int ulogd_keyh_ids;

/* allocate a new key_id */
static unsigned int keyh_allocid(ulog_interpreter_t *ip, unsigned int offset,
				const char *name)
{
	unsigned int id;

	id = ++ulogd_keyh_ids;

	if (id >= ulogd_keyh_ids_alloc) {
		if (!ulogd_keyh) {
			ulogd_keyh = (struct ulogd_keyh_entry *)
				malloc(KEYH_ALLOC_GRAN * 
					sizeof(struct ulogd_keyh_entry));
			if (!ulogd_keyh) {
				ulogd_log(ULOGD_ERROR, "OOM!\n");
				return 0;
			}
		} else {
			ulogd_keyh = (struct ulogd_keyh_entry *)
				realloc(ulogd_keyh, (KEYH_ALLOC_GRAN
						+ulogd_keyh_ids_alloc) *
					sizeof(struct ulogd_keyh_entry));

			if (!ulogd_keyh) {
				ulogd_log(ULOGD_ERROR, "OOM!\n");
				return 0;
			}
		}

		ulogd_keyh_ids_alloc += KEYH_ALLOC_GRAN;
	}

	ulogd_keyh[id].interp = ip;
	ulogd_keyh[id].offset = offset;
	ulogd_keyh[id].name = name;

	return id;
}

/* dump the keyhash to standard output */
static void keyh_dump(void)
{
	int i;

	printf("dumping keyh\n");
	for (i = 1; i <= ulogd_keyh_ids; i++)
		printf("ulogd_keyh[%d] = %s:%d\n", i, ulogd_keyh[i].interp->name, 
				ulogd_keyh[i].offset);
}

/* get keyid by name */
unsigned int keyh_getid(const char *name)
{
	int i;
	for (i = 1; i <= ulogd_keyh_ids; i++)
		if (!strcmp(name, ulogd_keyh[i].name))
			return i;

	return 0;
}

/* get key name by keyid */
char *keyh_getname(unsigned int id)
{
	if (id > ulogd_keyh_ids) {
		ulogd_log(ULOGD_NOTICE, 
			"keyh_getname called with invalid id%u\n", id);
		return NULL;
	}
		
	return ulogd_keyh[id].interp->name;
}

/* get result for given key id. does not check if result valid */
ulog_iret_t *keyh_getres(unsigned int id)
{
	ulog_iret_t *ret;

	if (id > ulogd_keyh_ids) {
		ulogd_log(ULOGD_NOTICE,
			"keyh_getres called with invalid id %d\n", id);
		return NULL;
	}

	ret = &ulogd_keyh[id].interp->result[ulogd_keyh[id].offset];

	return ret;
}

/***********************************************************************
 * INTERPRETER MANAGEMENT 
 ***********************************************************************

/* try to lookup a registered interpreter for a given name */
static ulog_interpreter_t *find_interpreter(const char *name)
{
	int id;
	
	id = interh_getid(name);
	if (!id)
		return NULL;

	return ulogd_interh[id];
}

/* the function called by all interpreter plugins for registering their
 * target. */ 
void register_interpreter(ulog_interpreter_t *me)
{
	int i;

	/* check if we already have an interpreter with this name */
	if (find_interpreter(me->name)) {
		ulogd_log(ULOGD_NOTICE, 
			"interpreter `%s' already registered\n", me->name);
		return;
	}

	ulogd_log(ULOGD_INFO, "registering interpreter `%s'\n", me->name);

	/* allocate a new interpreter id for it */
	if (!interh_allocid(me)) {
		ulogd_log(ULOGD_ERROR, "unable to obtain interh_id for "
			"interpreter '%s'\n", me->name);
		return;
	}

	/* - allocate one keyh_id for each result of this interpreter 
	 * - link the elements to each other */
	for (i = 0; i < me->key_num; i++) {
		if (!keyh_allocid(me, i, me->result[i].key)) {
			ulogd_log(ULOGD_ERROR, "unable to obtain keyh_id "
				"for interpreter %s, key %d", me->name,
				me->result[i].key);
			continue;
		}
		if (i != me->key_num - 1)
			me->result[i].next = &me->result[i+1];
	}

	/* all work done, we can prepend the new interpreter to the list */
	if (ulogd_interpreters)
		me->result[me->key_num - 1].next = &ulogd_interpreters->result[0];
	me->next = ulogd_interpreters;
	ulogd_interpreters = me;
}

/***********************************************************************
 * OUTPUT MANAGEMENT 
 ***********************************************************************

/* try to lookup a registered output plugin for a given name */
static ulog_output_t *find_output(const char *name)
{
	ulog_output_t *ptr;

	for (ptr = ulogd_outputs; ptr; ptr = ptr->next) {
		if (strcmp(name, ptr->name) == 0)
				return ptr;
	}

	return NULL;
}

/* the function called by all output plugins for registering themselves */
void register_output(ulog_output_t *me)
{
	if (find_output(me->name)) {
		ulogd_log(ULOGD_NOTICE, "output `%s' already registered\n",
				me->name);
		exit(1);
	}
	ulogd_log(ULOGD_NOTICE, "registering output `%s'\n", me->name);
	me->next = ulogd_outputs;
	ulogd_outputs = me;
}

/***********************************************************************
 * MAIN PROGRAM
 ***********************************************************************

/* log message to the logfile */
void ulogd_log(int level, const char *format, ...)
{
	char *timestr;
	va_list ap;
	time_t tm;
	FILE *outfd;

	/* log only messages which have level at least as high as loglevel */
	if (level < loglevel)
		return;

	if (logfile)
		outfd = logfile;
	else
		outfd = stderr;

	va_start(ap, format);

	tm = time(NULL);
	timestr = ctime(&tm);
	timestr[strlen(timestr)-1] = '\0';
	fprintf(outfd, "%s <%1.1d> %s:%d ", timestr, level, __FILE__, __LINE__);
	
	vfprintf(outfd, format, ap);
	va_end(ap);
}

/* propagate results to all registered output plugins */
static void propagate_results(ulog_iret_t *ret)
{
	ulog_output_t *p;

	for (p = ulogd_outputs; p; p = p->next) {
		(*p->output)(ret);
	}
}

/* clean results (set all values to 0 and free pointers) */
static void clean_results(ulog_iret_t *ret)
{
	ulog_iret_t *r;

	for (r = ret; r; r = r->next) {
		if (r->flags & ULOGD_RETF_FREE)
			free(r->value.ptr);
		memset(&r->value, 0, sizeof(r->value));
		r->flags &= ~ULOGD_RETF_VALID;
	}
}

/* call all registered interpreters and hand the results over to 
 * propagate_results */
static void handle_packet(ulog_packet_msg_t *pkt)
{
	ulog_iret_t *ret;
        ulog_iret_t *allret = NULL;
	ulog_interpreter_t *ip;

	unsigned int i,j;

	for (i = 1; i <= ulogd_interh_ids; i++) {
		ip = ulogd_interh[i];
		/* call interpreter */
		if ((ret = ((ip)->interp)(ip, pkt))) {
			/* create references for result linked-list */
			for (j = 0; j < ip->key_num; j++) {
				if (IS_VALID(ip->result[j])) {
					ip->result[j].cur_next = allret;
					allret = &ip->result[j];
				}
			}
		}
	}
	propagate_results(allret);
	clean_results(ulogd_interpreters->result);
}

/* plugin loader to dlopen() a plugins */
static int load_plugin(char *file)
{
	if (!dlopen(file, RTLD_NOW)) {
		ulogd_log(ULOGD_ERROR, "load_plugins: %s\n", dlerror());
		return 1;
	}
	return 0;
}

/* open the logfile */
static int logfile_open(const char *name)
{
	logfile = fopen(name, "a");
	if (!logfile) {
		fprintf(stderr, "ERROR: unable to open logfile %s: %s\n", 
			name, strerror(errno));
		exit(2);
	}
	return 0;
}

/* wrapper to handle conffile error codes */
static int parse_conffile(int final)
{
	int err;

	err = config_parse_file(final);

	switch(err) {
		case 0:
			return 0;
			break;
		case -ERROPEN:
			ulogd_log(ULOGD_ERROR,
				"unable to open configfile: %s\n",
				ULOGD_CONFIGFILE);
			break;
		case -ERRMAND:
			ulogd_log(ULOGD_ERROR,
				"mandatory option not found\n");
			break;
		case -ERRMULT:
			ulogd_log(ULOGD_ERROR,
				"option occurred more than once\n");
			break;
		case -ERRUNKN:
			ulogd_log(ULOGD_ERROR,
				"unknown config key\n");
/*				config_errce->key); */
			break;
	}
	return 1;

}

/* configuration directives of the main program */
static config_entry_t logf_ce = { NULL, "logfile", CONFIG_TYPE_STRING, 
				  CONFIG_OPT_NONE, 0, 
				  { string: ULOGD_LOGFILE_DEFAULT } };

static config_entry_t plugin_ce = { &logf_ce, "plugin", CONFIG_TYPE_CALLBACK,
				    CONFIG_OPT_MULTI, 0, 
				    { parser: &load_plugin } };

static config_entry_t nlgroup_ce = { &plugin_ce, "nlgroup", CONFIG_TYPE_INT,
				     CONFIG_OPT_NONE, 0,
				     { value: ULOGD_NLGROUP_DEFAULT } };

static config_entry_t loglevel_ce = { &nlgroup_ce, "loglevel", CONFIG_TYPE_INT,
				      CONFIG_OPT_NONE, 0, 
				      { value: 1 } };

static int init_conffile(char *file)
{
	if (config_register_file(file))
		return 1;

	config_register_key(&loglevel_ce);
	
	/* parse config file the first time (for logfile name, ...) */
	return parse_conffile(0);
}

int main(int argc, char* argv[])
{
	struct ipulog_handle *h;
	unsigned char* buf;
	size_t len;
	ulog_packet_msg_t *upkt;

	if (init_conffile(ULOGD_CONFIGFILE)) {
		ulogd_log(ULOGD_FATAL, "parse_conffile error\n");
		exit(1);
	}
	
	logfile_open(logf_ce.u.string);

	/* parse config file the second time (for plugin options) */
	if (parse_conffile(1)) {
		ulogd_log(ULOGD_FATAL, "parse_conffile\n");
		exit(1);
	}

#ifdef DEBUG
	/* dump key and interpreter hash */
	interh_dump();
	keyh_dump();
#endif

	/* allocate a receive buffer */
	buf = (unsigned char *) malloc(MYBUFSIZ);
	
	/* create ipulog handle */
	h = ipulog_create_handle(ipulog_group2gmask(nlgroup_ce.u.value));
	if (!h) {
		/* if some error occurrs, print it to stderr */
		ulogd_log(ULOGD_FATAL, "unable to create ipulogd handle\n");
		ipulog_perror(NULL);
		exit(1);
	}

#ifndef DEBUG
	if (!fork()) { 

		fclose(stdout);
		fclose(stderr);
#endif

		/* endless loop receiving packets and handling them over to
		 * handle_packet */
		while(1) {
			len = ipulog_read(h, buf, MYBUFSIZ, 1);
			while(upkt = ipulog_get_packet(h, buf, len)) {
				DEBUGP("==> packet received\n");
				handle_packet(upkt);
			}
		}
	
		/* just to give it a cleaner look */
		ipulog_destroy_handle(h);
		free(buf);
		fclose(logfile);
#ifndef DEBUG
	} else {
		exit(0);
	}
#endif
}