/* ulogd, Version $LastChangedRevision$
 *
 * $Id$
 *
 * unified network logging daemon for Linux.
 *
 * (C) 2000-2005 by Harald Welte <laforge@gnumonks.org>
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
 * Modifications:
 * 	14 Jun 2001 Martin Josefsson <gandalf@wlug.westbo.se>
 * 		- added SIGHUP handler for logfile cycling
 *
 * 	10 Feb 2002 Alessandro Bono <a.bono@libero.it>
 * 		- added support for non-fork mode
 * 		- added support for logging to stdout
 *
 * 	09 Sep 2003 Magnus Boden <sarek@ozaba.cx>
 * 		- added support for more flexible multi-section conffile
 *
 * 	20 Apr 2004 Nicolas Pougetoux <nicolas.pougetoux@edelweb.fr>
 * 		- added suppurt for seteuid()
 *
 * 	22 Jul 2004 Harald Welte <laforge@gnumonks.org>
 * 		- major restructuring for flow accounting / ipfix work
 *
 * 	03 Oct 2004 Harald Welte <laforge@gnumonks.org>
 * 		- further unification towards generic network event logging
 * 		  and support for lnstat
 *
 * 	17 Apr 2005 Harald Welte <laforge@gnumonks.org>
 * 		- 
 */

#define ULOGD_VERSION	"2.00alpha"

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <ctype.h>
#include <signal.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <dirent.h>
#include <getopt.h>
#include <pwd.h>
#include <grp.h>
#include <libipulog/libipulog.h>
#include <ulogd/conffile.h>
#include <ulogd/ulogd.h>
#include "select.h"
#ifdef DEBUG
#define DEBUGP(format, args...) fprintf(stderr, format, ## args)
#else
#define DEBUGP(format, args...) 
#endif

/* default config parameters, if not changed in configfile */
#ifndef ULOGD_LOGFILE_DEFAULT
#define ULOGD_LOGFILE_DEFAULT	"/var/log/ulogd.log"
#endif

/* where to look for the config file */
#ifndef ULOGD_CONFIGFILE
#define ULOGD_CONFIGFILE	"/etc/ulogd.conf"
#endif

#define COPYRIGHT \
	"Copyright (C) 2000-2005 Harald Welte <laforge@netfilter.org>\n"

/* global variables */
static FILE *logfile = NULL;		/* logfile pointer */
static int loglevel = 1;		/* current loglevel */
static char *ulogd_configfile = ULOGD_CONFIGFILE;

/* linked list for all registered interpreters */
//static struct ulog_interpreter *ulogd_interpreters;

/* linked list for all registered plugins */
static LIST_HEAD(ulogd_plugins);
static LIST_HEAD(ulogd_pi_stacks);

#if 0
/***********************************************************************
 * INTERPRETER AND KEY HASH FUNCTIONS 			(new in 0.9)
 ***********************************************************************/

/* We keep hashtables of interpreters and registered keys. The hash-tables
 * are allocated dynamically at program load time. You may control the
 e allocation granularity of both hashes (i.e. the amount of hashtable
 * entries are allocated at one time) through modification of the constants
 * INTERH_ALLOC_GRAN and KEYH_ALLOC_GRAN 
 */

/* allocation granularity */
#define INTERH_ALLOC_GRAN	5

/* hashtable for all registered interpreters */
static struct ulogd_interpreter **ulogd_interh;

/* current hashtable size */
static unsigned int ulogd_interh_ids_alloc;

/* total number of registered ids */
static unsigned int ulogd_interh_ids;

/* allocate a new interpreter id and write it into the interpreter struct */
static unsigned int interh_allocid(struct ulogd_interpreter *ip)
{
	unsigned int id;

	id = ++ulogd_interh_ids;
	
	if (id >= ulogd_interh_ids_alloc) {
		if (!ulogd_interh)
			ulogd_interh = (struct ulogd_interpreter **) 
				malloc(INTERH_ALLOC_GRAN *
					sizeof(struct ulogd_interpreter));
		else
			ulogd_interh = (struct ulogd_interpreter **)
				realloc(ulogd_interh, 
					(INTERH_ALLOC_GRAN +
					 ulogd_interh_ids_alloc) *
					sizeof(struct ulogd_interpreter));

		ulogd_interh_ids_alloc += INTERH_ALLOC_GRAN;
	}

	ip->id = id;
	ulogd_interh[id] = ip;
	return id;
}

/* get interpreter id by name */
unsigned int interh_getid(const char *name)
{
	unsigned int i;
	for (i = 1; i <= ulogd_interh_ids; i++)
		if (!strcmp(name, (ulogd_interh[i])->name))
			return i;

	return 0;
}

#ifdef DEBUG
/* dump out the contents of the interpreter hash */
static void interh_dump(void)
{
	unsigned int i;

	for (i = 1; i <= ulogd_interh_ids; i++)
		ulogd_log(ULOGD_DEBUG, "ulogd_interh[%d] = %s\n", 
			i, (ulogd_interh[i])->name);

}
#endif

/* key hash allocation granularity */
#define KEYH_ALLOC_GRAN 20

/* hash table for key ids */
struct ulogd_keyh_entry *ulogd_keyh;

/* current size of the hashtable */
static unsigned int ulogd_keyh_ids_alloc;

/* total number of registered keys */
static unsigned int ulogd_keyh_ids;

/* allocate a new key_id */
static unsigned int keyh_allocid(struct ulogd_interpreter *ip, unsigned int offset,
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

#ifdef DEBUG
/* dump the keyhash to standard output */
static void keyh_dump(void)
{
	unsigned int i;

	printf("dumping keyh\n");
	for (i = 1; i <= ulogd_keyh_ids; i++)
		printf("ulogd_keyh[%lu] = %s:%u\n", i, 
			ulogd_keyh[i].interp->name, ulogd_keyh[i].offset);
}
#endif

/* get keyid by name */
unsigned int keyh_getid(const char *name)
{
	unsigned int i;
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
struct ulogd_iret *keyh_getres(unsigned int id)
{
	struct ulogd_iret *ret;

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
 ***********************************************************************/

/* try to lookup a registered interpreter for a given name */
static struct ulogd_interpreter *find_interpreter(const char *name)
{
	unsigned int id;
	
	id = interh_getid(name);
	if (!id)
		return NULL;

	return ulogd_interh[id];
}

/* the function called by all interpreter plugins for registering their
 * target. */ 
void register_interpreter(struct ulogd_interpreter *me)
{
	unsigned int i;

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
		me->result[me->key_num - 1].next = 
					&ulogd_interpreters->result[0];
	me->next = ulogd_interpreters;
	ulogd_interpreters = me;
}
#endif

/***********************************************************************
 * PLUGIN MANAGEMENT 
 ***********************************************************************/

/* try to lookup a registered plugin for a given name */
static struct ulogd_plugin *find_plugin(const char *name)
{
	struct ulogd_plugin *pl;

	list_for_each_entry(pl, &ulogd_plugins, list) {
		if (strcmp(name, pl->name) == 0)
			return pl;
	}

	return NULL;
}

/* the function called by all plugins for registering themselves */
void register_plugin(struct ulogd_plugin *me)
{
	if (find_plugin(me->name)) {
		ulogd_log(ULOGD_NOTICE, "plugin `%s' already registered\n",
				me->name);
		exit(EXIT_FAILURE);
	}
	ulogd_log(ULOGD_NOTICE, "registering plugin `%s'\n", me->name);
	list_add(&me->list, &ulogd_plugins);
}

/***********************************************************************
 * MAIN PROGRAM
 ***********************************************************************/

/* log message to the logfile */
void __ulogd_log(int level, char *file, int line, const char *format, ...)
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
	fprintf(outfd, "%s <%1.1d> %s:%d ", timestr, level, file, line);
	
	vfprintf(outfd, format, ap);
	va_end(ap);

	/* flush glibc's buffer */
	fflush(outfd);
}

/* propagate results to all downstream plugins in the stack */
void ulogd_propagate_results(struct ulogd_pluginstance *pi)
{
	struct ulogd_pluginstance *cur = pi;
	/* iterate over remaining plugin stack */
	list_for_each_entry_continue(cur, &pi->stack->list, list) {
		int ret;
		
		ret = cur->plugin->interp(cur);
		switch (ret) {
		case ULOGD_IRET_ERR:
			ulogd_log(ULOGD_NOTICE,
				  "error during propagate_results\n");
			/* fallthrough */
		case ULOGD_IRET_STOP:
			/* we shall abort further iteration of the stack */
			return;
		case ULOGD_IRET_OK:
			/* we shall continue travelling down the stack */
			continue;
		default:
			ulogd_log(ULOGD_NOTICE,
				  "unknown return value `%d' from plugin %s\n",
				  ret, cur->plugin->name);
			break;
		}
	}
}

#if 0
/* clean results (set all values to 0 and free pointers) */
static void clean_results(struct ulogd_iret *ret)
{
	struct ulogd_iret *r;

	for (r = ret; r; r = r->next) {
		if (r->flags & ULOGD_RETF_FREE) {
			free(r->value.ptr);
			r->value.ptr = NULL;
		}
		memset(&r->value, 0, sizeof(r->value));
		r->flags &= ~ULOGD_RETF_VALID;
	}
}
#endif

static struct ulogd_pluginstance *
pluginstance_alloc_init(struct ulogd_plugin *pl, char *pi_id,
			struct ulogd_pluginstance_stack *stack)
{
	unsigned int size;
	struct ulogd_pluginstance *pi;
	void *ptr;

	size = sizeof(struct ulogd_pluginstance);
	size += pl->priv_size;
	size += sizeof(struct config_keyset);
	size += pl->config_kset->num_ces * sizeof(struct config_entry);
	size += pl->input.num_keys * sizeof(struct ulogd_key);
	size += pl->output.num_keys * sizeof(struct ulogd_key);
	pi = malloc(size);
	if (!pi)
		return NULL;

	/* initialize */
	memset(pi, 0, size);
	INIT_LIST_HEAD(&pi->list);
	pi->plugin = pl;
	pi->stack = stack;
	memcpy(pi->id, pi_id, sizeof(pi->id));

	ptr = (void *)pi + sizeof(*pi);

	ptr += pl->priv_size;
	/* copy config keys */
	pi->config_kset = ptr;
	pi->config_kset->num_ces = pl->config_kset->num_ces;
	memcpy(pi->config_kset->ces, pl->config_kset->ces, 
	       pi->config_kset->num_ces * sizeof(struct config_entry));

	/* copy input keys */
	ptr += sizeof(struct config_keyset);
	ptr += pi->config_kset->num_ces * sizeof(struct config_entry);
	pi->input = ptr;
	memcpy(pi->input, pl->input.keys, 
	       pl->input.num_keys * sizeof(struct ulogd_key));
	
	/* copy input keys */
	ptr += pl->input.num_keys * sizeof(struct ulogd_key);
	pi->output = ptr;
	memcpy(pi->output, pl->output.keys, 
	       pl->output.num_keys * sizeof(struct ulogd_key));

	return pi;
}


/* plugin loader to dlopen() a plugins */
static int load_plugin(char *file)
{
	if (!dlopen(file, RTLD_NOW)) {
		ulogd_log(ULOGD_ERROR, "load_plugins: '%s': %s\n", file,
			  dlerror());
		return 1;
	}
	return 0;
}

/* find an output key in a given stack, starting at 'start' */
static struct ulogd_key *
find_okey_in_stack(char *name,
		   struct ulogd_pluginstance_stack *stack,
		   struct ulogd_pluginstance *start)
{
	struct ulogd_pluginstance *pi;

	list_for_each_entry_reverse(pi, &start->list, list) {
		int i;

		if ((void *)&pi->list == stack)
			return NULL;

		for (i = 0; i < pi->plugin->output.num_keys; i++) {
			struct ulogd_key *okey = &pi->output[i];
			if (!strcmp(name, okey->name))
				return okey;
		}
	}

	return NULL;
}

/* resolve key connections from bottom to top of stack */
static int
create_stack_resolve_keys(struct ulogd_pluginstance_stack *stack)
{
	int i = 0;
	struct ulogd_pluginstance *pi_cur;

	/* PASS 2: */
	ulogd_log(ULOGD_DEBUG, "connecting input/output keys of stack:\n");
	list_for_each_entry_reverse(pi_cur, &stack->list, list) {
		struct ulogd_pluginstance *pi_prev = 
					list_entry(pi_cur->list.prev,
						   struct ulogd_pluginstance,
						   list);
		if (i == 0) {
			/* first round: output plugin */
			if (pi_cur->plugin->output.type != ULOGD_DTYPE_SINK) {
				ulogd_log(ULOGD_ERROR, "last plugin in stack "
					  "has to be output plugin\n");
				return -EINVAL;
			}
			/* continue further down */
		} /* no "else' since first could be the last one, too ! */

		if (&pi_prev->list == &stack->list) {
			/* this is the last one in the stack */
			if (pi_cur->plugin->input.type != ULOGD_DTYPE_SOURCE) {
				ulogd_log(ULOGD_ERROR, "first plugin in stack "
					  "has to be source plugin\n");
				return -EINVAL;
			}
			/* no need to match keys */
		} else {
			int j;

			/* not the last one in the stack */
			if (pi_cur->plugin->input.type != 
					pi_prev->plugin->output.type) {
				ulogd_log(ULOGD_ERROR, "type mismatch between "
					  "%s and %s in stack\n",
					  pi_cur->plugin->name,
					  pi_prev->plugin->name);
			}
			/* call plugin to tell us which keys it requires in
			 * given configuration */
			if (pi_cur->plugin->configure) {
				int ret = pi_cur->plugin->configure(pi_cur, 
								    stack);
				if (ret < 0) {
					ulogd_log(ULOGD_ERROR, "error during "
						  "configure of plugin %s\n",
						  pi_cur->plugin->name);
					return ret;
				}
			}

			for (j = 0; j < pi_cur->plugin->input.num_keys; j++) {
				struct ulogd_key *okey;
				struct ulogd_key *ikey = 
					&pi_cur->plugin->input.keys[i];

				/* skip those marked as 'inactive' by
				 * pl->configure() */
				if (ikey->flags & ULOGD_KEYF_INACTIVE)
					continue;

				if (ikey->u.source) { 
					ulogd_log(ULOGD_ERROR, "key `%s' "
						  "already has source\n",
						  ikey->name);
					return -EINVAL;
				}

				okey = find_okey_in_stack(ikey->name, 
							  stack, pi_cur);
				if (!okey && 
				    !(ikey->flags & ULOGD_KEYF_OPTIONAL)) {
					ulogd_log(ULOGD_ERROR, "cannot find "
						  "key `%s' in stack\n",
						  ikey->name);
					return -EINVAL;
				}

				ikey->u.source = okey;
			}
		}
	}

	return 0;
}

/* create a new stack of plugins */
static int create_stack(char *option)
{
	struct ulogd_pluginstance_stack *stack;
	char *buf = strdup(option);
	char *tok;
	int ret;

	if (!buf) {
		ulogd_log(ULOGD_ERROR, "");
		return 1;
	}

	stack = malloc(sizeof(*stack));
	if (!stack)
		return -ENOMEM;
	INIT_LIST_HEAD(&stack->list);

	ulogd_log(ULOGD_DEBUG, "building new pluginstance stack:\n");

	/* PASS 1: find and instanciate plugins of stack, link them together */
	for (tok = strtok(buf, ",\n"); tok; tok = strtok(NULL, ",\n")) {
		char *plname, *equals;
		char pi_id[ULOGD_MAX_KEYLEN];
		struct ulogd_pluginstance *pi;
		struct ulogd_plugin *pl;

		/* parse token into sub-tokens */
		equals = strchr(tok, '=');
		if (!equals || (equals - tok >= ULOGD_MAX_KEYLEN)) {
			ulogd_log(ULOGD_ERROR, "syntax error while parsing `%s'"
				  "of line `%s'\n", tok, buf);
			free(stack);
			return -EINVAL;
		}
		strncpy(pi_id, tok, ULOGD_MAX_KEYLEN-1);
		pi_id[equals-tok] = '\0';
		plname = equals+1;
	
		/* find matching plugin */
 		pl = find_plugin(plname);
		if (!pl) {
			ulogd_log(ULOGD_ERROR, "can't find requested plugin "
				  "%s\n", plname);
			free(stack);
			return -ENODEV;
		}

		/* allocate */
		pi = pluginstance_alloc_init(pl, pi_id, stack);
		if (!pi) {
			ulogd_log(ULOGD_ERROR, 
				  "unable to allocate pluginstance for %s\n",
				  pi_id);
			free(stack);
			return -ENOMEM;
		}
	
		/* FIXME: call constructor routine from end to beginning,
		 * fix up input/output keys */
			
		ulogd_log(ULOGD_DEBUG, "pushing `%s' on stack\n", pl->name);
		list_add(&pi->list, &stack->list);
	}

	ret = create_stack_resolve_keys(stack);
	if (ret < 0) {
		free(stack);
		return ret;
	}

	/* add head of pluginstance stack to list of stacks */
	list_add(&stack->stack_list, &ulogd_pi_stacks);
	return 0;
}
	

static int ulogd_main_loop(void)
{
	int ret = 0;

	while (1) {
		ret = ulogd_select_main();
		if (ret == 0) 
			continue;

		if (ret < 0) {
			if (errno == -EINTR)
				continue;
			else {
				ulogd_log(ULOGD_ERROR, "select returned %s\n",
					  strerror(errno));
				break;
			}
		}
	}

	return ret;
}

/* open the logfile */
static int logfile_open(const char *name)
{
	if (!strcmp(name,"stdout")) {
		logfile = stdout;
	} else {
		logfile = fopen(name, "a");
		if (!logfile) {
			fprintf(stderr, "ERROR: can't open logfile %s: %s\n", 
				name, strerror(errno));
			exit(2);
		}
	}
	ulogd_log(ULOGD_INFO, "ulogd Version %s starting\n", ULOGD_VERSION);
	return 0;
}

/* wrapper to handle conffile error codes */
static int parse_conffile(const char *section, struct config_keyset *ce)
{
	int err;

	err = config_parse_file(section, ce);

	switch(err) {
		case 0:
			return 0;
			break;
		case -ERROPEN:
			ulogd_log(ULOGD_ERROR,
				"unable to open configfile: %s\n",
				ulogd_configfile);
			break;
		case -ERRMAND:
			ulogd_log(ULOGD_ERROR,
				"mandatory option \"%s\" not found\n",
				config_errce->key);
			break;
		case -ERRMULT:
			ulogd_log(ULOGD_ERROR,
				"option \"%s\" occurred more than once\n",
				config_errce->key);
			break;
		case -ERRUNKN:
			ulogd_log(ULOGD_ERROR,
				"unknown config key \"%s\"\n",
				config_errce->key);
			break;
		case -ERRSECTION:
			ulogd_log(ULOGD_ERROR,
				"section \"%s\" not found\n", section);
			break;
	}
	return 1;

}


static struct config_keyset ulogd_kset = {
	.num_ces = 4,
	.ces = {
		{
			.key = "logfile",
			.type = CONFIG_TYPE_STRING, 
			.options = CONFIG_OPT_NONE,
			.u.string = ULOGD_LOGFILE_DEFAULT,
		},
		{
			.key = "plugin",
			.type = CONFIG_TYPE_CALLBACK,
			.options = CONFIG_OPT_MULTI,
			.u.parser = &load_plugin,
		},
		{
			.key = "loglevel", 
			.type = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = 1,
		},
		{
			.key = "stack",
			.type = CONFIG_TYPE_CALLBACK,
			.options = CONFIG_OPT_NONE,
			.u.parser = &create_stack,
		},
	},
};

#define logfile_ce	ulogd_kset.ces[0]
#define plugin_ce	ulogd_kset.ces[1]
#define loglevel_ce	ulogd_kset.ces[2]
#define stack_ce	ulogd_kset.ces[3]


static void deliver_signal_pluginstances(int signal)
{
	struct ulogd_pluginstance_stack *stack;
	struct ulogd_pluginstance *pi;

	list_for_each_entry(stack, &ulogd_pi_stacks, stack_list) {
		list_for_each_entry(pi, &stack->list, list) {
			if (pi->plugin->signal)
				(*pi->plugin->signal)(pi, signal);
		}
	}
}

static void sigterm_handler(int signal)
{
	
	ulogd_log(ULOGD_NOTICE, "sigterm received, exiting\n");

	deliver_signal_pluginstances(signal);

	if (logfile != stdout)
		fclose(logfile);

	exit(0);
}

static void signal_handler(int signal)
{
	ulogd_log(ULOGD_NOTICE, "signal received, calling pluginstances\n");
	
	deliver_signal_pluginstances(signal);

	/* reopen logfile */
	if (logfile != stdout) {
		fclose(logfile);
		logfile = fopen(logfile_ce.u.string, "a");
		if (!logfile)
			sigterm_handler(signal);
	}
}

static void print_usage(void)
{
	/* FIXME */
	printf("ulogd Version %s\n", ULOGD_VERSION);
	printf(COPYRIGHT);
	printf("This is free software with ABSOLUTELY NO WARRANTY.\n\n");
	printf("Parameters:\n");
	printf("\t-h --help\tThis help page\n");
	printf("\t-V --version\tPrint version information\n");
	printf("\t-d --daemon\tDaemonize (fork into background)\n");
	printf("\t-c --configfile\tUse alternative Configfile\n");
	printf("\t-u --uid\tChange UID/GID\n");
}

static struct option opts[] = {
	{ "version", 0, NULL, 'V' },
	{ "daemon", 0, NULL, 'd' },
	{ "help", 0, NULL, 'h' },
	{ "configfile", 1, NULL, 'c'},
	{ "uid", 1, NULL, 'u' },
	{ 0 }
};

int main(int argc, char* argv[])
{
	int argch;
	int daemonize = 0;
	int change_uid = 0;
	char *user = NULL;
	struct passwd *pw;
	uid_t uid = 0;
	gid_t gid = 0;


	while ((argch = getopt_long(argc, argv, "c:dh::Vu:", opts, NULL)) != -1) {
		switch (argch) {
		default:
		case '?':
			if (isprint(optopt))
				fprintf(stderr, "Unknown option `-%c'.\n", 
					optopt);
			else
				fprintf(stderr, "Unknown option character "
					"`\\x%x'.\n", optopt);

			print_usage();
			exit(1);
			break;
		case 'h':
			print_usage();
			exit(0);
			break;
		case 'd':
			daemonize = 1;
			break;
		case 'V':
			printf("ulogd Version %s\n", ULOGD_VERSION);
			printf(COPYRIGHT);
			exit(0);
			break;
		case 'c':
			ulogd_configfile = optarg;
			break;
		case 'u':
			change_uid = 1;
			user = strdup(optarg);
			pw = getpwnam(user);
			if (!pw) {
				printf("Unknown user %s.\n", user);
				free(user);
				exit(1);
			}
			uid = pw->pw_uid;
			gid = pw->pw_gid;
			break;
		}
	}

	if (config_register_file(ulogd_configfile)) {
		ulogd_log(ULOGD_FATAL, "error registering configfile \"%s\"\n",
			  ulogd_configfile);
		exit(1);
	}
	
	/* parse config file */
	if (parse_conffile("global", &ulogd_kset)) {
		ulogd_log(ULOGD_FATAL, "parse_conffile\n");
		exit(1);
	}

	if (change_uid) {
		ulogd_log(ULOGD_NOTICE, "Changing UID / GID\n");
		if (setgid(gid)) {
			ulogd_log(ULOGD_FATAL, "can't set GID %u\n", gid);
			ipulog_perror(NULL);
			exit(1);
		}
		if (setegid(gid)) {
			ulogd_log(ULOGD_FATAL, "can't sett effective GID %u\n",
				  gid);
			ipulog_perror(NULL);
			exit(1);
		}
		if (initgroups(user, gid)) {
			ulogd_log(ULOGD_FATAL, "can't set user secondary GID\n");
			ipulog_perror(NULL);
			exit(1);
		}
		if (setuid(uid)) {
			ulogd_log(ULOGD_FATAL, "can't set UID %u\n", uid);
			ipulog_perror(NULL);
			exit(1);
		}
		if (seteuid(uid)) {
			ulogd_log(ULOGD_FATAL, "can't set effective UID %u\n",
				  uid);
			ipulog_perror(NULL);
			exit(1);
		}
	}

	logfile_open(logfile_ce.u.string);

#ifdef DEBUG
	/* dump key and interpreter hash */
	interh_dump();
	keyh_dump();
#endif
	if (daemonize){
		if (fork()) {
			exit(0);
		}
		if (logfile != stdout)
			fclose(stdout);
		fclose(stderr);
		fclose(stdin);
		setsid();
	}

	signal(SIGTERM, &sigterm_handler);
	signal(SIGHUP, &signal_handler);

	ulogd_log(ULOGD_NOTICE, 
		  "initialization finished, entering main loop\n");

	ulogd_main_loop();

	/* hackish, but result is the same */
	sigterm_handler(SIGTERM);	
	return(0);
}
