/* ulogd, Version $Revision: 1.10 $
 *
 * first try of a logging daemon for my netfilter ULOG target
 * for the linux 2.4 netfilter subsystem.
 *
 * (C) 2000 by Harald Welte <laforge@sunbeam.franken.de>
 *
 * this code is released under the terms of GNU GPL
 *
 * $Id: ulogd.c,v 1.10 2000/09/12 14:29:37 laforge Exp $
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

#define MYBUFSIZ 2048

#ifdef DEBUG
#define DEBUGP(format, args...) fprintf(stderr, format, ## args)
#else
#define DEBUGP(format, args...) 
#endif

/* default config parameters, if not changed in configfile */
#ifndef ULOGD_PLUGINDIR_DEFAULT
#define ULOGD_PLUGINDIR_DEFAULT	"/usr/local/lib/ulogd"
#endif
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
/* linked list for all registered interpreters */
static ulog_interpreter_t *ulogd_interpreters;

/* linked list for all registered output targets */
static ulog_output_t *ulogd_outputs;

/***********************************************************************
 * INTERPRETER AND KEY HASH FUNCTIONS
 ***********************************************************************/

/* hashtable for all registered interpreters */
static ulog_interpreter_t *ulogd_interh[100];
static unsigned int ulogd_interh_ids;

/* allocate a new interpreter id and write it into the interpreter struct */
static unsigned int interh_allocid(ulog_interpreter_t *ip)
{
	unsigned int id;

	id = ++ulogd_interh_ids;
	ip->id = id;
	ulogd_interh[id] = ip;
	return id;
}

/* get interpreter d by name */
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
		printf("ulogd_interh[%d] = %s\n", i, (ulogd_interh[i])->name);

}

struct ulogd_keyh_entry {
	ulog_interpreter_t *interp;	/* interpreter for this key */
	unsigned int offset;		/* offset within interpreter */
	const char *name;		/* name of this particular key */
};

static struct ulogd_keyh_entry ulogd_keyh[100];
static unsigned int ulogd_keyh_ids;

/* allocate a new key_id */
static unsigned int keyh_allocid(ulog_interpreter_t *ip, unsigned int offset,
				const char *name)
{
	unsigned int id;

	id = ++ulogd_keyh_ids;

	ulogd_keyh[id].interp = ip;
	ulogd_keyh[id].offset = offset;
	ulogd_keyh[id].name = name;

	return id;
}

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
inline char *keyh_getname(unsigned int id)
{
	return ulogd_keyh[id].interp->name;
}


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
		ulogd_error("interpreter `%s' already registered\n",
				me->name);
		exit(1);
	}

	ulogd_log(ULOGD_NOTICE, "registering interpreter `%s'\n", me->name);

	/* allocate a new interpreter id for it */
	interh_allocid(me);

	/* - allocate one keyh_id for each result of this interpreter 
	 * - link the elements to each other */
	for (i = 0; i < me->key_num; i++) {
		keyh_allocid(me, i, me->result[i].key);
		if (i != me->key_num - 1)
			me->result[i].next = &me->result[i+1];
	}

	if (ulogd_interpreters)
		me->result[me->key_num - 1].next = &ulogd_interpreters->result[0];

	/* all work done, we can prepend the new interpreter to the list */
	me->next = ulogd_interpreters;
	ulogd_interpreters = me;
}

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
		ulogd_error("output `%s' already registered\n",
				me->name);
		exit(1);
	}
	ulogd_log(ULOGD_NOTICE, "registering output `%s'\n", me->name);
	me->next = ulogd_outputs;
	ulogd_outputs = me;
}

/* allocate a new ulog_iret_t. Called by interpreter plugins */
ulog_iret_t *alloc_ret(const u_int16_t type, const char* key)
{
	ulog_iret_t *ptr = NULL;
	
	ptr = (ulog_iret_t *) malloc(sizeof(ulog_iret_t));
	memset(ptr, 0, sizeof(ulog_iret_t));
	strcpy(ptr->key, key);
	ptr->type = type;

	return ptr;
}

/* log message to the logfile */
void ulogd_log(int level, const char *format, ...)
{
	char *timestr;
	va_list ap;
	time_t tm;
	FILE *outfd;

	if (logfile)
		outfd = logfile;
	else
		outfd = stderr;

	va_start(ap, format);

	tm = time(NULL);
	timestr = ctime(&tm);
	timestr[strlen(timestr)-1] = '\0';
	fprintf(outfd, "%s <%1.1d>", timestr, level);
	
	vfprintf(outfd, format, ap);
	va_end(ap);
}
/* this should pass the result(s) to one or more registered output plugins,
 * but is currently only printing them out */
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

#define IS_VALID(x)	(x.flags & ULOGD_RETF_VALID)

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
		if (ret = ((ip)->interp)(ip, pkt)) {
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

/* silly plugin loader to dlopen() all available plugins */
static void load_plugins(char *dir)
{
	DIR *ldir;
	struct dirent *dent;
	char *fname;

	ldir = opendir(dir);
	if (ldir) {
		fname = (char *) malloc(NAME_MAX + strlen(dir) 
				+ 3);
		for (dent = readdir(ldir); dent; dent = readdir(ldir)) {
			if (strncmp(dent->d_name,"ulogd", 5) == 0) {
			DEBUGP("load_plugins: %s\n", dent->d_name);
			sprintf(fname, "%s/%s", dir, dent->d_name);
			if (!dlopen(fname, RTLD_NOW))
				ulogd_error("load_plugins: %s\n", dlerror());
			}
		}
		free(fname);
	} else
		ulogd_error("No plugin directory: %s\n", dir);

	interh_dump();
	keyh_dump();

}

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

static int parse_conffile(int final)
{
	int err;

	err = config_parse_file(final);

	switch(err) {
		case 0:
			return 0;
			break;
		case -ERROPEN:
			ulogd_error("ERROR: unable to open configfile: %s\n",
					ULOGD_CONFIGFILE);
			break;
		case -ERRMAND:
			ulogd_error("ERROR: mandatory option not found\n");
			break;
		case -ERRMULT:
			ulogd_error("ERROR: option occurred more than once\n");
			break;
		case -ERRUNKN:
			ulogd_error("ERROR: unknown config key\n");
				config_errce->key);
			break;
	}
	return 1;

}

static config_entry_t logf_ce = { NULL, "logfile", CONFIG_TYPE_STRING, 
				  CONFIG_OPT_NONE, 0, 
				  { string: ULOGD_LOGFILE_DEFAULT } };
				  
static config_entry_t pldir_ce = { NULL, "plugindir", CONFIG_TYPE_STRING,
				   CONFIG_OPT_NONE, 0, 
				   { string: ULOGD_PLUGINDIR_DEFAULT } };

static config_entry_t nlgroup_ce = { NULL, "nlgroup", CONFIG_TYPE_INT,
				     CONFIG_OPT_NONE, 0,
				     { value: ULOGD_NLGROUP_DEFAULT } };
static int init_conffile(char *file)
{
	if (config_register_file(file))
		return 1;

	/* link them together */
	logf_ce.next = &pldir_ce;
	pldir_ce.next = &nlgroup_ce;

	config_register_key(&logf_ce);
	
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
		exit(1);
	}
	
	logfile_open(logf_ce.u.string);
	load_plugins(pldir_ce.u.string);	

	/* parse config file the second time (for plugin options) */
	if (parse_conffile(1)) {
		ulogd_error("ERROR during second parse_conffile\n");
		exit(1);
	}

	/* allocate a receive buffer */
	buf = (unsigned char *) malloc(MYBUFSIZ);
	
	/* create ipulog handle */
	h = ipulog_create_handle(ipulog_group2gmask(nlgroup_ce.u.value));
	if (!h) {
		/* if some error occurrs, print it to stderr */
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
			upkt = ipulog_get_packet(buf);	
			DEBUGP("==> packet received\n");
			handle_packet(upkt);
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
