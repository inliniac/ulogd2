/* config file parser functions
 *
 * (C) 2000 by Harald Welte <laforge@gnumonks.org>
 *
 * $Id: conffile.c,v 1.1 2000/11/20 11:43:22 laforge Exp $
 * 
 * This code is distributed under the terms of GNU GPL */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "conffile.h"

#ifdef DEBUG_CONF
#define DEBUGC(format, args...) fprintf(stderr, format, ## args)
#else
#define DEBUGC(format, args...)
#endif

/* linked list of all registered configuration directives */
static config_entry_t *config = NULL;

/* points to config entry with error */
config_entry_t *config_errce = NULL;

/* Filename of the config file */
static char *fname = NULL;

/* get_word() - Function to parse a line into words.
 * Arguments:	line	line to parse
 * 		delim	possible word delimiters
 * 		buf	pointer to buffer where word is returned
 * Return value:	pointer to first char after word
 * This function can deal with "" quotes 
 */
char* get_word(char *line, char *not, char *buf)
{
	char *p, *start = NULL, *stop = NULL;
	int inquote = 0;

	for (p = line; *p; p++) {
		if (*p == '"') {
			start  = p + 1;
			inquote = 1;
			break;
		}
		if (!strchr(not, *p)) {
			start = p;
			break;
		}
	}
	if (!start)
		return NULL;

	/* determine pointer to one char after word */
	for (p = start; *p; p++) {
		if (inquote) {
			if (*p == '"') {
				stop = p;
				break;
			}
		} else {
			if (strchr(not, *p)) {
				stop = p;
				break;
			}
		}
	}
	if (!stop)
		return NULL;

	strncpy(buf, start, stop-start);
	*(buf + (stop-start)) = '\0';

	/* skip quote character */
	if (inquote)
		/* yes, we can return stop + 1. If " was the last 
		 * character in string, it now points to NULL-term */
		return (stop + 1);

	return stop;
}

/* do we have a config directive for this name */
static int config_iskey(char *name)
{
	config_entry_t *ce;

	for (ce = config; ce; ce = ce->next) {
		if (!strcmp(name, ce->key))
			return 0;
	}

	return 1;
}

/***********************************************************************
 * PUBLIC INTERFACE
 ***********************************************************************/

/* register linked list of config directives with us */
int config_register_key(config_entry_t *ce)
{
	config_entry_t *myentry;

	if (!ce)
		return 1;

	/* prepend our list to the global config list */
	for (myentry = ce; myentry->next; myentry = myentry->next) {
	}
	myentry->next = config;
	config = ce;

	return 0;
}

/* register config file with us */
int config_register_file(const char *file)
{
	/* FIXME: stat of file */
	if (fname)
		return 1;

	fname = (char *) malloc(strlen(file)+1);
	if (!fname)
		return -ERROOM;

	strcpy(fname, file);

	return 0;
}

/* parse config file */
int config_parse_file(int final)
{
	FILE *cfile;
	char *line, *args;
	config_entry_t *ce;
	int err = 0;

	line = (char *) malloc(LINE_LEN+1);	
	if (!line) 
		return -ERROOM;
	
	cfile = fopen(fname, "r");
	if (!cfile) {
		free(line);
		return -ERROPEN;
	}
	
	while (fgets(line, LINE_LEN, cfile))
	{
		char wordbuf[LINE_LEN];
		char *wordend;
		
		DEBUGC("line read: %s\n", line);
		if (*line == '#')
			continue;

		if (!(wordend = get_word(line, " \t\n", (char *) &wordbuf)))
			continue;
#if 0
		/* if we do the final parse and word is not a config key */
		if (final && config_iskey(word)) {
			DEBUGC("final and key '%s' not found\n", word);
			err = -ERRUNKN;
			goto cpf_error;
		}
#endif

		DEBUGC("parse_file: entering main loop\n");
		for (ce = config; ce; ce = ce->next) {
			DEBUGC("parse main loop, key: %s\n", ce->key);
			if (strcmp(ce->key, (char *) &wordbuf)) {
				continue;
			}

			wordend = get_word(wordend, " \t\n", (char *) &wordbuf);
			args = (char *)&wordbuf;

			if (ce->hit && !(ce->options & CONFIG_OPT_MULTI))
			{
				DEBUGC("->ce-hit and option not multi!\n");
				config_errce = ce;
				err = -ERRMULT;
				goto cpf_error;
			}
			if (final) 
				ce->hit++;
			switch (ce->type) {
				case CONFIG_TYPE_STRING:
					if (strlen(args) < 
					    CONFIG_VAL_STRING_LEN ) {
						strcpy(ce->u.string, args);
						/* FIXME: what if not ? */
					}
					break;
				case CONFIG_TYPE_INT:
					ce->u.value = atoi(args);
					break;
				case CONFIG_TYPE_CALLBACK:
					(ce->u.parser)(args);
					break;
			}
			break;
		}
		DEBUGC("parse_file: exiting main loop\n");
	}


	for (ce = config; ce; ce = ce->next) {
		DEBUGC("ce post loop, ce=%s\n", ce->key);
		if ((ce->options & CONFIG_OPT_MANDATORY) && (ce->hit == 0) && final) {
			DEBUGC("mandatory config directive %s not found\n",
				ce->key);
			config_errce = ce;
			err = -ERRMAND;
			goto cpf_error;
		}

	}

cpf_error:
	free(line);
	fclose(cfile);
	return err;
}

