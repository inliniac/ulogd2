/* ulogd, Version $Revision: 1.7 $
 *
 * first try of a logging daemon for my netfilter ULOG target
 * for the linux 2.4 netfilter subsystem.
 *
 * (C) 2000 by Harald Welte <laforge@sunbeam.franken.de>
 *
 * this code is released under the terms of GNU GPL
 *
 * $Id: ulogd.c,v 1.7 2000/09/09 18:35:26 laforge Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

/* try to lookup a registered interpreter for a given name */
static ulog_interpreter_t *find_interpreter(const char *name)
{
	ulog_interpreter_t *ptr;

	for (ptr = ulogd_interpreters; ptr; ptr = ptr->next) {
		if (strcmp(name, ptr->name) == 0)
				return ptr;
	}

	return NULL;
}

/* the function called by all interpreter plugins for registering their
 * target. */ 
void register_interpreter(ulog_interpreter_t *me)
{
	if (find_interpreter(me->name)) {
		ulogd_error("interpreter `%s' already registered\n",
				me->name);
		exit(1);
	}
	DEBUGP("registering interpreter `%s'\n", me->name);
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
	DEBUGP("registering output `%s'\n", me->name);
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

/* free a ulog_iret_t* including all linked ones and the value pointers */
void free_ret(ulog_iret_t *ret)
{
	ulog_iret_t *ptr = NULL;
	ulog_iret_t *nextptr = NULL;

	for (ptr = ret; ptr; ptr = nextptr) {
		if ((ptr->type | 0x7fff) == 0xffff) {
			free(ptr->value.ptr);
			}
		if (ptr->next) {
			nextptr = ptr->next;
		} else {
			nextptr = NULL;
		}
		free(ptr);
	}
}

void ulogd_log(int level, const char *message)
{
	char *timestr;

	timestr = ctime(time());
	fprintf(logfile, "%s <%1.1d> %s\n", timestr, level, message);

}
/* this should pass the result(s) to one or more registered output plugins,
 * but is currently only printing them out */
static void propagate_results(ulog_iret_t *ret)
{
	ulog_output_t *p;

	for (p = ulogd_outputs; p; p = p->next)
	{
		(*p->output)(ret);
	}
}

/* call all registered interpreters and hand the results over to 
 * propagate_results */
static void handle_packet(ulog_packet_msg_t *pkt)
{
	ulog_interpreter_t *ptr;
	ulog_iret_t *ret, *b;
        ulog_iret_t *allret = NULL;

	/* call each registered interpreter */
	for (ptr = ulogd_interpreters; ptr; ptr = ptr->next) {
		ret = (*ptr->interp)(pkt);
		if (ret) {
			/* prepend the results to allret */
			if (allret) { 
				for (b = ret; b->next; b = b->next);
				b->next = allret;
			}
			allret = ret;
		}
	}	
	propagate_results(allret);
	free_ret(allret);
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
				ulogd_error("load_plugins: %s", dlerror());
			}
		}
		free(fname);
	} else
		ulogd_error("No plugin directory: %s\n", dir);

}

static int logfile_open(const char *name)
{
	logfile = fopen(name, "a");
	if (!logfile) 
	{
		fprintf(stderr, "ERROR: unable to open logfile %s: %s\n", 
			name, strerror(errno));
		exit(2);
	}
	return 0;
}

static int parse_conffile(char *file, int final)
{
	int err;
	FILE *outfd;

	err = config_parse_file(file, final);

	if (logfile)
		outfd = logfile;
	else
		outfd = stderr;

	switch(err) {
		case 0:
			return 0;
			break;
		case -ERROPEN:
			fprintf(outfd, "ERROR: unable to open configfile: %s\n",
					ULOGD_CONFIGFILE);
			break;
		case -ERRMAND:
			fprintf(outfd, "ERROR: mandatory option not found\n");
			break;
		case -ERRMULT:
			fprintf(outfd, "ERROR: option occurred more than once\n");
			break;
		case -ERRUNKN:
			fprintf(outfd, "ERROR: unknown config key\n");
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
	/* linke them together */
	logf_ce.next = &pldir_ce;
	pldir_ce.next = &nlgroup_ce;

	config_register_key(&logf_ce);
	
	/* parse config file the first time (for logfile name, ...) */
	return parse_conffile(file, 0);
}

int main(int argc, char* argv[])
{
	struct ipulog_handle *h;
	unsigned char* buf;
	size_t len;
	ulog_packet_msg_t *upkt;

	if (init_conffile(ULOGD_CONFIGFILE))
	{
		DEBUGP("ERROR during init_configfile\n");
		exit(1);
	}

	
	logfile_open(logf_ce.u.string);
	load_plugins(pldir_ce.u.string);	

	/* parse config file the second time (for plugin options) */
	if (parse_conffile(ULOGD_CONFIGFILE, 1))
	{
		ulogd_error("ERROR during second parse_conffile\n");
		exit(1);
	}

	/* allocate a receive buffer */
	buf = (unsigned char *) malloc(MYBUFSIZ);
	
	/* create ipulog handle */
	h = ipulog_create_handle(ipulog_group2gmask(nlgroup_ce.u.value));
	if (!h)
	{
		/* if some error occurrs, print it to stderr */
		ipulog_perror(NULL);
		exit(1);
	}

#ifndef DEBUG
	if (!fork())
	{ 

		fclose(stdout);
		fclose(stderr);
#endif

		/* endless loop receiving packets and handling them over to
		 * handle_packet */
		while(1)
		{
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
	} else
	{
		exit(0);
	}
#endif
}
