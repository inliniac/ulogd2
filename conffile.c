/* config file parser functions
 * (C) 2000 by Harald Welte <laforge@gnumonks.org>
 *
 * $Id: conffile.c,v 1.2 2000/09/09 18:27:23 laforge Exp $
 * 
 * This code is distributed under the terms of GNU GPL */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "conffile.h"

#ifdef DEBUG_CONF
#define DEBUGC(format, args...) fprintf(stderr, format ## args)
#else
#define DEBUGC(format, args...)
#endif

static config_entry_t *config = NULL;
config_entry_t *config_errce = NULL;

static char *get_word(const char *string)
{
	int len;
	char *word, *space;
	space = strchr(string, ' ');

	if (!space) {
		space = strchr(string, '\t');
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

	if (*(word + len) == '\n')
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

int config_register_key(config_entry_t *ce)
{
	ce->next = config;
	ce->hit = 0;
	config = ce;
	return 0;
}

int config_parse_file(const char *fname, int final)
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
	
	while (line = fgets(line, LINE_LEN, cfile))
	{
		if (*line == '#')
			continue;

		word = get_word(line);
		if (!word)
			continue;

		/* if we do the final parse and word is not a config key */
		if (final && !config_iskey(word)) {
			err = -ERRUNKN;
			config_errce = ce;
			goto cpf_error;
		}

		args = line + strlen(word) + 1;
		*(args + strlen(args) - 1 ) = '\0';

		for (ce = config; ce; ce = ce->next) {
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

