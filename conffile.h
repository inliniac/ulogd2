/* config file parser functions
 * (C) 2000 by Harald Welte <laforge@gnumonks.org>
 *
 * $Id$
 * 
 * This code is distributed under the terms of GNU GPL */

#include <sys/types.h>

/* errors returned by config functions */
enum {
	ERRNONE = 0,
	ERROPEN,	/* unable to open config file */
	ERROOM,		/* out of memory */
	ERRMULT,	/* non-multiple option occured more  than once */
	ERRMAND,	/* mandatory option not found */
};

/* maximum line lenght of config file entries */
#define LINE_LEN 255

/* maximum lenght of config key name */
#define CONFIG_KEY_LEN	30

#define CONFIG_TYPE_INT		0x0001
#define CONFIG_TYPE_STRING	0x0002
#define CONFIG_TYPE_CALLBACK	0x0003

#define CONFIG_OPT_MANDATORY	0x0001
#define CONFIG_OPT_MULTI	0x0002

typedef struct config_entry {
	struct config_entry *next;
	char key[CONFIG_KEY_LEN];
	u_int8_t type;
	u_int8_t options;
	u_int8_t hit;
	union {
		struct {
			char *string;
			int maxlen;
		} str;
		int value;
		int (*parser)(char *argstr);
	} u;
} config_entry_t;
	
int config_parse_file(const char *fname);
int config_register_key(config_entry_t *ce);
