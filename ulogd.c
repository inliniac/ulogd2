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

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <dirent.h>
#include <libipulog/libipulog.h>
#include "ulogd.h"

#define MYBUFSIZ 2048

#define ulogd_error(format, args...) fprintf(stderr, format, ## args)
#define DEBUGP ulogd_error

#define ULOGD_PLUGIN_DIR	"/usr/local/lib/ulogd"
#define NIPQUAD(addr) \
        ((unsigned char *)&addr)[0], \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[3]

/* linked list for all registered interpreters */
static ulog_interpreter_t *ulogd_interpreters;

/* try to lookup a registered interpreter for a given name */
ulog_interpreter_t *find_interpreter(const char *name)
{
	ulog_interpreter_t *ptr;

	for (ptr = ulogd_interpreters; ptr; ptr = ptr->next) {
		if (strcmp(name, ptr->name) == 0)
				break;
	}

	return ptr;
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
		free(ptr->value);
		if (ptr->next) {
			nextptr = ptr->next;
		} else {
			nextptr = NULL;
		}
		free(ptr);
	}
}

/* this should pass the result(s) to one or more registered output plugins,
 * but is currently only printing them out */
void propagate_results(ulog_iret_t *res)
{
	ulog_iret_t *ret;

	for (ret = res; ret; ret = ret->next)
	{
		printf("%s=", ret->key);
		switch (ret->type) {
			case ULOGD_RET_STRING:
				printf("%s\n", ret->value);
				break;
			case ULOGD_RET_INT16:
			case ULOGD_RET_INT32:
				printf("%d\n", ret->value);
				break;
			case ULOGD_RET_UINT8:
				printf("%u\n", *(u_int8_t *)ret->value);
				break;
			case ULOGD_RET_UINT16:
				printf("%u\n", *(u_int16_t *)ret->value);
				break;
			case ULOGD_RET_UINT32:
			case ULOGD_RET_UINT64:
				printf("%lu\n", *(u_int32_t *)ret->value);
				break;
			case ULOGD_RET_IPADDR:
				printf("%u.%u.%u.%u\n", 
					NIPQUAD(*(u_int32_t *)ret->value));
				break;
			case ULOGD_RET_NONE:
				printf("<none>");
				break;
		}
	}
}

/* call all registered interpreters and hand the results over to 
 * propagate_results */
void handle_packet(ulog_packet_msg_t *pkt)
{
	ulog_interpreter_t *ptr;
	ulog_iret_t *ret;

	for (ptr = ulogd_interpreters; ptr; ptr = ptr->next) {
		ret = (*ptr->interp)(pkt);
		if (ret) {
			propagate_results(ret);
			free_ret(ret);
		}
	}	
}

/* silly plugin loader to dlopen() all available plugins */
void load_plugins(void)
{
	DIR *ldir;
	struct dirent *dent;
	char *fname;

	ldir = opendir(ULOGD_PLUGIN_DIR);
	if (ldir) {
		fname = (char *) malloc(NAME_MAX + strlen(ULOGD_PLUGIN_DIR) 
				+ 3);
		for (dent = readdir(ldir); dent; dent = readdir(ldir)) {
			DEBUGP("load_plugins: %s\n", dent->d_name);
			sprintf(fname, "%s/%s", ULOGD_PLUGIN_DIR, dent->d_name);
			if (!dlopen(fname, RTLD_NOW))
				ulogd_error("load_plugins: %s", dlerror());
		}
		free(fname);
	} else
		ulogd_error("no plugin directory\n");

}

main(int argc, char* argv[])
{
	struct ipulog_handle *h;
	unsigned char* buf;
	size_t len;
	ulog_packet_msg_t *upkt;

	load_plugins();	
	
	/* allocate a receive buffer */
	buf = (unsigned char *) malloc(MYBUFSIZ);
	
	/* create ipulog handle */
	h = ipulog_create_handle(ipulog_group2gmask(32));
	if (!h)
	{
		/* if some error occurrs, print it to stderr */
		ipulog_perror(NULL);
		exit(1);
	}

	/* endless loop receiving packets and handling them over to
	 * handle_packet */
	while(1)
	{
		len = ipulog_read(h, buf, BUFSIZ, 1);
		upkt = ipulog_get_packet(buf);	
		DEBUGP("==> packet received\n");
		handle_packet(upkt);
	}
	
	/* just to give it a cleaner look */
	ipulog_destroy_handle(h);

}
