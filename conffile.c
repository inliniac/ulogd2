/* config file parser functions
 * (C) 2000 by Harald Welte <laforge@gnumonks.org>
 *
 * $Id$
 * 
 * This code is distributed under the terms of GNU GPL */

#include <stdio.h>
#include <string.h>
#include "conffile.h"

#ifdef DEBUG_CONF
#define DEBUGC(format, args...) fprintf(stderr, format ## args)
#else
#define DEBUGC 
#endif

static config_entry_t *config = NULL;

static char *get_word(const char *string)
{
	int len;
	char *word, *space;
	space = strchr(string, ' ');
	if (!space)
		return NULL;
	len = space - string;
	word = (char *) malloc(len+1);
	if (!word)
		return NULL;
	strncpy(word, string, len);

	return word;
}

int config_register_key(config_entry_t *ce)
{
	ce->next = config;
	ce->hit = 0;
	config = ce;
	return 0;
}

int config_parse_file(const char *fname)
{
	FILE *cfile;
	char *line, *word, *args;
	config_entry_t *ce;

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

		args = line + strlen(word) + 1;

		for (ce = config; ce; ce = ce->next) {
			if (strcmp(ce->key, word)) {
				continue;
			}
			if (ce->hit && !(ce->options & CONFIG_OPT_MULTI))
			{
				DEBUGC("->ce-hit and option not multi!\n");
				free(line);
				fclose(cfile);
				return -ERRMULT;
			}
			ce->hit++;
			switch (ce->type) {
				case CONFIG_TYPE_STRING:
					if (strlen(args) <= ce->u.str.maxlen) {
						strcpy(ce->u.str.string, args);
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
			free(line);
			fclose(cfile);
			return -ERRMAND;
		}

	}

	fclose(cfile);
	return 0;
}

