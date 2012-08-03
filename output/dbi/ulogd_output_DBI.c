/* ulogd_DBI.c, Version $Revision$
 *
 * ulogd output plugin for logging to a database using the DBI abstraction
 * layer
 *
 * (C) 2000-2008 by Pierre Chifflier <chifflier@inl.fr>
 * This software is distributed under the terms of GNU GPL 
 * 
 * This plugin is based on the PostgreSQL plugin made by Harald Welte.
 *
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

#include <ulogd/ulogd.h>
#include <ulogd/conffile.h>
#include <ulogd/db.h>

#include <dbi.h>

#include <ctype.h>

#ifdef DEBUG_DBI
#define DEBUGP(x, args...)	fprintf(stderr, x, ## args)
#else
#define DEBUGP(x, args...)
#endif

struct dbi_instance {
	struct db_instance db_inst;

	dbi_conn dbh;
	dbi_result result;
};
#define TIME_ERR	((time_t)-1)

/* our configuration directives */
static struct config_keyset dbi_kset = {
	.num_ces = DB_CE_NUM + 7,
	.ces = {
		DB_CES,
		{ 
			.key = "db", 
			.type = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_MANDATORY,
		},
		{
			.key = "host", 
			.type = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_NONE,
		},
		{ 
			.key = "user", 
			.type = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_MANDATORY,
		},
		{
			.key = "pass", 
			.type = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_NONE,
		},
		{
			.key = "port",
			.type = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
		},
		{
			.key = "schema", 
			.type = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_NONE,
			.u.string = "public",
		},
		{ 
			.key = "dbtype", 
			.type = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_MANDATORY,
		},
	},
};
#define db_ce(x)	(x->ces[DB_CE_NUM+0])
#define host_ce(x)	(x->ces[DB_CE_NUM+1])
#define user_ce(x)	(x->ces[DB_CE_NUM+2])
#define pass_ce(x)	(x->ces[DB_CE_NUM+3])
#define port_ce(x)	(x->ces[DB_CE_NUM+4])
#define schema_ce(x)	(x->ces[DB_CE_NUM+5])
#define dbtype_ce(x)	(x->ces[DB_CE_NUM+6])


/* lower-cases s in place */
static void str_tolower(char *s)
{
	while(*s) {
		*s = tolower(*s);
		s++;
	}
}

/* find out which columns the table has */
static int get_columns_dbi(struct ulogd_pluginstance *upi)
{
	struct dbi_instance *pi = (struct dbi_instance *) upi->private;
	char *table = table_ce(upi->config_kset).u.string;
	char query[256];
	unsigned int ui;

	if (!pi->dbh) {
		ulogd_log(ULOGD_ERROR, "no database handle\n");
		return 1;
	}

	snprintf(query, 256, "SELECT * FROM %s", table);

	ulogd_log(ULOGD_DEBUG, "%s\n", query);
	pi->result = dbi_conn_query(pi->dbh,query);
	if (!pi->result) {
		const char *errptr;
		dbi_conn_error(pi->dbh, &errptr);
		ulogd_log(ULOGD_DEBUG, "Could not fetch columns (%s)",
			  errptr);
		return -1;
	}

	if (upi->input.keys)
		free(upi->input.keys);

	upi->input.num_keys = dbi_result_get_numfields(pi->result);
	ulogd_log(ULOGD_DEBUG, "%u fields in table\n", upi->input.num_keys);

	upi->input.keys = malloc(sizeof(struct ulogd_key) *
						upi->input.num_keys);
	if (!upi->input.keys) {
		upi->input.num_keys = 0;
		ulogd_log(ULOGD_ERROR, "ENOMEM\n");
		dbi_result_free(pi->result);
		return -ENOMEM;
	}

	memset(upi->input.keys, 0, sizeof(struct ulogd_key) *
						upi->input.num_keys);

	for (ui=1; ui<=upi->input.num_keys; ui++) {
		char buf[ULOGD_MAX_KEYLEN+1];
		char *underscore;
		const char* field_name = dbi_result_get_field_name(pi->result, ui);

		if (!field_name)
			break;

		/* replace all underscores with dots */
		strncpy(buf, field_name, ULOGD_MAX_KEYLEN);
		while ((underscore = strchr(buf, '_')))
			*underscore = '.';

		str_tolower(buf);

		DEBUGP("field '%s' found: ", buf);

		/* add it to list of input keys */
		strncpy(upi->input.keys[ui-1].name, buf, ULOGD_MAX_KEYLEN);
	}

	/* ID is a sequence */
	upi->input.keys[0].flags |= ULOGD_KEYF_INACTIVE;

	dbi_result_free(pi->result);

	return 0;
}

static int close_db_dbi(struct ulogd_pluginstance *upi)
{
	struct dbi_instance *pi = (struct dbi_instance *) upi->private;

	ulogd_log(ULOGD_DEBUG, "dbi: closing connection\n");
	dbi_conn_close(pi->dbh);
	pi->dbh = NULL;
	//dbi_shutdown();

	return 0;
}

/* make connection and select database */
static int open_db_dbi(struct ulogd_pluginstance *upi)
{
	struct dbi_instance *pi = (struct dbi_instance *) upi->private;
	char *server = host_ce(upi->config_kset).u.string;
	char *user = user_ce(upi->config_kset).u.string;
	char *pass = pass_ce(upi->config_kset).u.string;
	char *db = db_ce(upi->config_kset).u.string;
	char *dbtype = dbtype_ce(upi->config_kset).u.string;
	dbi_driver driver;
	int ret;

	if (pi->dbh != NULL)
		return 0;

	ulogd_log(ULOGD_ERROR, "Opening connection for db type %s\n",
		  dbtype);
	driver = dbi_driver_open(dbtype);
	if (driver == NULL) {
		ulogd_log(ULOGD_ERROR, "unable to load driver for db type %s\n",
			  dbtype);
		close_db_dbi(upi);
		return -1;
	}
	pi->dbh = dbi_conn_new(dbtype);
	if (pi->dbh == NULL) {
		ulogd_log(ULOGD_ERROR, "unable to initialize db type %s\n",
			  dbtype);
		close_db_dbi(upi);
		return -1;
	}

	if (server)
		dbi_conn_set_option(pi->dbh, "host", server);
	if (user)
		dbi_conn_set_option(pi->dbh, "username", user);
	if (pass)
		dbi_conn_set_option(pi->dbh, "password", pass);
	if (db)
		dbi_conn_set_option(pi->dbh, "dbname", db);

	ret = dbi_conn_connect(pi->dbh);
	if (ret < 0) {
		ulogd_log(ULOGD_ERROR, "unable to connect to db %s\n",
			  db);
		close_db_dbi(upi);
		return -1;
	}

	return 0;
}

static int escape_string_dbi(struct ulogd_pluginstance *upi,
			     char *dst, const char *src, unsigned int len)
{
	struct dbi_instance *pi = (struct dbi_instance *) upi->private;
	char *newstr;
	int ret;

	if (len == 0) {
		*dst = '\0';
		return 0;
	}

	ret = dbi_conn_quote_string_copy(pi->dbh, src, &newstr);
	if (ret <= 2)
		return 0;

	/* dbi_conn_quote_string_copy returns a quoted string,
	 * but __interp_db already quotes the string
	 * So we return a string without the quotes
	 */
	strncpy(dst,newstr+1,ret-2);
	dst[ret-2] = '\0';
	free(newstr);

	return (ret-2);
}

static int execute_dbi(struct ulogd_pluginstance *upi,
			 const char *stmt, unsigned int len)
{
	struct dbi_instance *pi = (struct dbi_instance *) upi->private;

	pi->result = dbi_conn_query(pi->dbh,stmt);
	if (!pi->result) {
		const char *errptr;
		dbi_conn_error(pi->dbh, &errptr);
		ulogd_log(ULOGD_ERROR, "execute failed (%s)\n",
			  errptr);
		ulogd_log(ULOGD_DEBUG, "failed query: [%s]\n",
			  stmt);
		return -1;
	}

	dbi_result_free(pi->result);

	return 0;
}

static struct db_driver db_driver_dbi = {
	.get_columns	= &get_columns_dbi,
	.open_db	= &open_db_dbi,
	.close_db	= &close_db_dbi,
	.escape_string	= &escape_string_dbi,
	.execute	= &execute_dbi,
};

static int configure_dbi(struct ulogd_pluginstance *upi,
			 struct ulogd_pluginstance_stack *stack)
{
	struct dbi_instance *pi = (struct dbi_instance *) upi->private;

	pi->db_inst.driver = &db_driver_dbi;

	return ulogd_db_configure(upi, stack);
}

static struct ulogd_plugin dbi_plugin = { 
	.name 		= "DBI", 
	.input 		= {
		.keys	= NULL,
		.num_keys = 0,
		.type	= ULOGD_DTYPE_PACKET | ULOGD_DTYPE_FLOW,
	},
	.output 	= {
		.type	= ULOGD_DTYPE_SINK,
	},
	.config_kset 	= &dbi_kset,
	.priv_size	= sizeof(struct dbi_instance),
	.configure	= &configure_dbi,
	.start		= &ulogd_db_start,
	.stop		= &ulogd_db_stop,
	.signal		= &ulogd_db_signal,
	.interp		= &ulogd_db_interp,
	.version	= VERSION,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	dbi_initialize(NULL);

	ulogd_register_plugin(&dbi_plugin);
}
