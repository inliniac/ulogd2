/* config file parser functions
 *
 * (C) 2000 by Harald Welte <laforge@gnumonks.org>
 *
 * $Id: conffile.c,v 1.7 2000/11/16 17:20:52 laforge Exp $
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

/* the the next word in string */
static char *get_word(const char *string)
{
	int len;
	char *word, *space;
	space = strrchr(string, ' ');

	if (!space) {
		space = strrchr(string, '\t');
		if (!space)
			return NULL;
	}
	len = space - string;
	if (!len) 
		return NULL;

	word = (char *) malloc(len+1);
	if (!word)
		return NULL;

	strncpy(word, string, len);

//	if (*(word + len) == '\n')
		*(word + len) = '\0';

	return word;
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
	char *line, *word, *args;
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
		DEBUGC("line read: %s\n", line);
		if (*line == '#')
			continue;

		word = get_word(line);
		if (!word)
			continue;

#if 0
		/* if we do the final parse and word is not a config key */
		if (final && config_iskey(word)) {
			DEBUGC("final and key '%s' not found\n", word);
			err = -ERRUNKN;
			goto cpf_error;
		}
#endif

		args = line + strlen(word) + 1;
		*(args + strlen(args) - 1 ) = '\0';
		
		DEBUGC("parse_file: entering main loop\n");
		for (ce = config; ce; ce = ce->next) {
			DEBUGC("parse main loop, key: %s\n", ce->key);
			if (strcmp(ce->key, word)) {
				continue;
			}

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

