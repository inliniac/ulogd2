/* config file parser functions
 * (C) 2000 by Harald Welte <laforge@gnumonks.org>
 *
 * $Id: conffile.c,v 1.5 2000/09/12 14:29:36 laforge Exp $
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

static config_entry_t *config = NULL;

config_entry_t *config_errce = NULL;

static char *fname = NULL;

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
		DEBUGC("line read\n");
		if (*line == '#')
			continue;

		word = get_word(line);
		if (!word)
			continue;

		/* if we do the final parse and word is not a config key */
		if (final && config_iskey(word)) {
			DEBUGC("final and key '%s' not found\n", word);
			err = -ERRUNKN;
			goto cpf_error;
		}

		args = line + strlen(word) + 1;
		*(args + strlen(args) - 1 ) = '\0';

		for (ce = config; ce; ce = ce->next) {
			DEBUGC("parse main loop\n");
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
	}


	for (ce = config; ce; ce = ce->next) {
		DEBUGC("ce post loop, ce=%s\n", ce->key);
		if ((ce->options & CONFIG_OPT_MANDATORY) && (ce->hit == 0)) {
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

