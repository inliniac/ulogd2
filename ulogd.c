/* ulogd, Version $LastChangedRevision$
 *
 * $Id$
 *
 * unified network logging daemon for Linux.
 *
 * (C) 2000-2004 by Harald Welte <laforge@gnumonks.org>
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
 * $Id$
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

/* global variables */
static FILE *logfile = NULL;		/* logfile pointer */
static int loglevel = 1;		/* current loglevel */
static char *ulogd_configfile = ULOGD_CONFIGFILE;

/* linked list for all registered interpreters */
//static struct ulog_interpreter *ulogd_interpreters;

/* linked list for all registered plugins */
static struct ulogd_plugin *ulogd_plugins;
static LIST_HEAD(ulogd_pi_stacks);
static LIST_HEAD(ulogd_fds);

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

/***********************************************************************
 * PLUGIN MANAGEMENT 
 ***********************************************************************/

/* try to lookup a registered plugin for a given name */
static struct ulogd_plugin *find_plugin(const char *name)
{
	struct ulogd_plugin *ptr;

	for (ptr = ulogd_outputs; ptr; ptr = ptr->next) {
		if (strcmp(name, ptr->name) == 0)
				return ptr;
	}

	return NULL;
}

/* the function called by all plugins for registering themselves */
void register_plugin(struct ulogd_plugin *me)
{
	if (find_plugin(me->name)) {
		ulogd_log(ULOGD_NOTICE, "output `%s' already registered\n",
				me->name);
		exit(EXIT_FAILURE);
	}
	ulogd_log(ULOGD_NOTICE, "registering plugin `%s'\n", me->name);
	me->next = ulogd_plugins;
	ulogd_plugins = me;
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

/* propagate results to all registered output plugins */
static void propagate_results(struct ulogd_iret *ret)
{
	struct ulogd_plugin *p;

	for (p = ulogd_outputs; p; p = p->next) {
		(*p->output)(ret);
	}
}

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



static struct ulogd_pluginstance *
pluginstance_alloc_init(struct ulogd_plugin *pl, char *pi_id,
			struct ulogd_pluginstance *stack)
{
	unsigned int ce_size;
	struct ulogd_pluginstance *pi = malloc(sizeof(struct ulogd_pluginstance)+len);
	if (!pi)
		return NULL;

	/* initialize */
	memset(pi, 0, sizeof(struct ulogd_pluginstance)+len);
	INIT_LIST_HEAD(&pi->list);
	pi->plugin = pl;
	memcpy(pi->id, pi_id, sizeof(pi->id));

	/* copy config keys */
	pi->config_kset.num_ces = pl->config_kset.num_ces;
	ce_size = pl->config_kset.num_ces*sizeof(struct config_entry);
	pi->config_kset.ces = malloc(ce_size);
	if (!pi->configs) {
		free(pi);
		return NULL;
	}
	memcpy(pi->config_kset.ces, pl->config_kset.ces, ce_size);
	
	/* FIXME: allocate input and output keys ?*/

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

/* create a new stack of plugins */
static int create_stack(char *option)
{
	struct ulogd_pluginstance *stack = NULL;
	char *buf = strdup(option);
	char *tok;

	if (!buf) {
		ulogd_log(ULOGD_EROR, "");
		return 1;
	}

	ulogd_log(ULOGD_DEBUG, "building new pluginstance stack:\n");

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
		}
		strncpy(pi_id, tok, ULOGD_MAX_KEYLEN-1);
		pi_id[equals-tok] = '\0';
		plname = equals+1;

		/* find matching plugin */
 		pl = find_plugin(plname);
		if (!pl) {
			ulogd_log(ULOGD_ERROR, "can't find requested plugin "
				  "%s\n", );
			return 1;
		}

		/* allocate */
		pi = ulogd_pluginstance_alloc_init(pl. pi_id, stack);
		if (!pi) {
			ulogd_log(ULOGD_ERROR, 
				  "unable to allocate pluginstance for %s\n",
				  pi_id);
			return 1;
		}

		/* FIXME: call constructor routine from end to beginning,
		 * fix up input/output keys */
			
		ulogd_log(ULOGD_DEBUG, "pushing `%s' on stack\n", pl->name);
		if (!stack)
			stack = pi;
		else
			list_add(&pi->list, &stack->list);
	}
	/* add head of pluginstance stack to list of stacks */
	list_add(&stack->stack_list, &ulogd_pi_stacks);
	return 0;
}

int ulogd_register_fd(struct ulogd_fd *ufd)
{
	list_add(&ufd->list, &ulogd_fds);
}

void ulogd_unregister_fd(struct ulogd_fd *ufd)
{
	list_del(&ufd->list);
}

int ulogd_main_loop()
{
	fd_set read_fd, write_fd, except_fd;
	unsigned int hifd;
	struct ulogd_fd *ufd;

	while (1) {
		FD_ZERO(&read_fd);
		FD_ZERO(&write_fd);
		FD_ZERO(&except_fd);
		hifd = 0;
		list_for_each_entry(ufd, &ulogd_fds, list) {
			if (ufd->when & ULOGD_FD_READ)
				FD_SET(ufd->fd, &read_fd);
			if (ufd->when & ULOGD_FD_WRITE)
				FD_SET(ufd->fd, &write_fd);
			if (ufd->when & ULOGD_FD_EXCEPT)
				FD_SET(ufd->fd, &except_fd);

			if (ufd->fd > hifd)
				hifd = ufd;
		}

		ret = select(hifd+1, &read_fd, &write_fd, &except_fd, NULL);

		list_for_each_entry(ufd, &ulogd_fds, list) {
			unsigned int what = 0;
			if (FD_ISSET(ufd->fd, &read_fd))
				what |= ULOGD_FD_READ;
			if (FD_ISSET(ufd->fd, &write_fd))
				what |= ULOGD_FD_WRITE;
			if (FD_ISSET(ufd->fd, &except_fd))
				what |= ULOGD_FD_EXCEPT;

			if (what & ufd->when)
				ufd->cb(ufd->fd, what, ufd->data);
		}
	}

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

/* configuration directives of the main program */
static struct config_entry ulogd_ces[] = {
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
};

static struct config_keyset ulogd_kset = {
	.ces = &ulogd_ces,
	.num_ces = sizeof(ulogd_ces)/sizeof(struct config_entry),
};

#define logfile_ce	ulogd_ces[0]
#define plugin_ce	ulogd_ces[1]
#define loglevel_ce	ulogd_ces[2]
#define stack_ce	ulogd_ces[3]
					

static void sigterm_handler(int signal)
{
	struct ulogd_plugin *p;
	
	ulogd_log(ULOGD_NOTICE, "sigterm received, exiting\n");

	ipulog_destroy_handle(libulog_h);
	free(libulog_buf);
	if (logfile != stdout)
		fclose(logfile);

	for (p = ulogd_outputs; p; p = p->next) {
		if (p->fini)
			(*p->fini)();
	}

	exit(0);
}

static void sighup_handler(int signal)
{
	struct ulogd_plugin *p;

	if (logfile != stdout) {
		fclose(logfile);
		logfile = fopen(logf_ce.u.string, "a");
		if (!logfile)
			sigterm_handler(signal);
	}

	ulogd_log(ULOGD_NOTICE, "sighup received, calling plugin handlers\n");
	
	for (p = ulogd_outputs; p; p = p->next) {
		if (p->signal)
			(*p->signal)(SIGHUP);
	}
}

static void print_usage(void)
{
	/* FIXME */
	printf("ulogd Version %s\n", ULOGD_VERSION);
	printf("Copyright (C) 2000-2005 Harald Welte "
	       "<laforge@gnumonks.org>\n");
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
	int len;
	int argch;
	int daemonize = 0;
	int change_uid = 0;
	char *user = NULL;
	struct passwd *pw;
	uid_t uid = 0;
	gid_t gid = 0;
	ulog_packet_msg_t *upkt;
	ulog_output_t *p;


	while ((argch = getopt_long(argc, argv, "c:dh::Vu:", opts, NULL)) != -1) {
		switch (argch) {
		default:
		case '?':
			if (isprint(optopt))
				fprintf(stderr, "Unknown option `-%c'.\n", optopt);
			else
				fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);

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
			printf("Copyright (C) 2000-2005 Harald Welte "
			       "<laforge@gnumonks.org>\n");
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

	logfile_open(logf_ce.u.string);

	for (p = ulogd_outputs; p; p = p->next) {
		if (p->init)
			(*p->init)();
	}

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
	signal(SIGHUP, &sighup_handler);

	ulogd_log(ULOGD_NOTICE, 
		  "initialization finished, entering main loop\n");

	/* hackish, but result is the same */
	sigterm_handler(SIGTERM);	
	return(0);
}
