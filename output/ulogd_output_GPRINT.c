/* ulogd_GPRINT.c
 *
 * ulogd output target for logging to a file in comma-separated key-value.
 * This is a generalization of ulogd_GPRINT.c
 *
 * (C) 2000-2005 by Harald Welte <laforge@gnumonks.org>
 * (C) 2012 by Pablo Neira Ayuso <pablo@netfilter.org>
 * (C) 2012 by Intra2net AG <http://www.intra2net.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <inttypes.h>
#include <ulogd/ulogd.h>
#include <ulogd/conffile.h>

#ifndef ULOGD_GPRINT_DEFAULT
#define ULOGD_GPRINT_DEFAULT	"/var/log/ulogd.gprint"
#endif

struct gprint_priv {
	FILE *of;
};

enum gprint_conf {
	GPRINT_CONF_FILENAME = 0,
	GPRINT_CONF_SYNC,
	GPRINT_CONF_TIMESTAMP,
	GPRINT_CONF_MAX
};

static struct config_keyset gprint_kset = {
	.num_ces = GPRINT_CONF_MAX,
	.ces = {
		[GPRINT_CONF_FILENAME] = {
			.key = "file",
			.type = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_NONE,
			.u = {.string = ULOGD_GPRINT_DEFAULT },
		},
		[GPRINT_CONF_SYNC] = {
			.key = "sync",
			.type = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u = { .value = 0 },
		},
		[GPRINT_CONF_TIMESTAMP] = {
			.key = "timestamp",
			.type = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u = { .value = 0 },
		},
	},
};

#define NIPQUAD(addr) \
        ((unsigned char *)&addr)[0], \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[3]

static int gprint_interp(struct ulogd_pluginstance *upi)
{
	struct gprint_priv *opi = (struct gprint_priv *) &upi->private;
	unsigned int i;
	char buf[4096];
	int rem = sizeof(buf), size = 0, ret;

	if (upi->config_kset->ces[GPRINT_CONF_TIMESTAMP].u.value != 0) {
		struct tm tm;
		time_t now;

		now = time(NULL);
		localtime_r(&now, &tm);

		ret = snprintf(buf+size, rem,
				"timestamp=%.4u/%.2u/%.2u-%.2u:%.2u:%.2u,",
				1900 + tm.tm_year, tm.tm_mon + 1, tm.tm_mday,
				tm.tm_hour, tm.tm_min, tm.tm_sec);
		if (ret < 0)
			return ULOGD_IRET_OK;
		rem -= ret;
		size += ret;
	}

	for (i = 0; i < upi->input.num_keys; i++) {
		struct ulogd_key *key = upi->input.keys[i].u.source;

		if (!key)
			continue;

		if (!IS_VALID(*key))
			continue;

		switch (key->type) {
		case ULOGD_RET_STRING:
			ret = snprintf(buf+size, rem, "%s=", key->name);
			if (ret < 0)
				break;
			rem -= ret;
			size += ret;

			ret = snprintf(buf+size, rem, "%s,",
					(char *) key->u.value.ptr);
			if (ret < 0)
				break;
			rem -= ret;
			size += ret;
			break;
		case ULOGD_RET_BOOL:
		case ULOGD_RET_INT8:
		case ULOGD_RET_INT16:
		case ULOGD_RET_INT32:
			ret = snprintf(buf+size, rem, "%s=", key->name);
			if (ret < 0)
				break;
			rem -= ret;
			size += ret;

			ret = snprintf(buf+size, rem, "%d,", key->u.value.i32);
			if (ret < 0)
				break;
			rem -= ret;
			size += ret;
			break;
		case ULOGD_RET_UINT8:
		case ULOGD_RET_UINT16:
		case ULOGD_RET_UINT32:
		case ULOGD_RET_UINT64:
			ret = snprintf(buf+size, rem, "%s=", key->name);
			if (ret < 0)
				break;
			rem -= ret;
			size += ret;

			ret = snprintf(buf+size, rem, "%" PRIu64 ",",
					key->u.value.ui64);
			if (ret < 0)
				break;
			rem -= ret;
			size += ret;
			break;
		case ULOGD_RET_IPADDR:
			ret = snprintf(buf+size, rem, "%s=", key->name);
			if (ret < 0)
				break;
			rem -= ret;
			size += ret;

			ret = snprintf(buf+size, rem, "%u.%u.%u.%u,",
				NIPQUAD(key->u.value.ui32));
			if (ret < 0)
				break;
			rem -= ret;
			size += ret;
			break;
		default:
			/* don't know how to interpret this key. */
			break;
		}
	}
	buf[size-1]='\0';
	fprintf(opi->of, "%s\n", buf);

	if (upi->config_kset->ces[GPRINT_CONF_SYNC].u.value != 0)
		fflush(opi->of);

	return ULOGD_IRET_OK;
}

static void sighup_handler_print(struct ulogd_pluginstance *upi, int signal)
{
	struct gprint_priv *oi = (struct gprint_priv *) &upi->private;
	FILE *old = oi->of;

	switch (signal) {
	case SIGHUP:
		ulogd_log(ULOGD_NOTICE, "GPRINT: reopening logfile\n");
		oi->of = fopen(upi->config_kset->ces[0].u.string, "a");
		if (!oi->of) {
			ulogd_log(ULOGD_ERROR, "can't open GPRINT "
					       "log file: %s\n",
				  strerror(errno));
			oi->of = old;
		} else {
			fclose(old);
		}
		break;
	default:
		break;
	}
}

static int gprint_configure(struct ulogd_pluginstance *upi,
			    struct ulogd_pluginstance_stack *stack)
{
	int ret;

	ret = ulogd_wildcard_inputkeys(upi);
	if (ret < 0)
		return ret;

	ret = config_parse_file(upi->id, upi->config_kset);
	if (ret < 0)
		return ret;

	return 0;
}

static int gprint_init(struct ulogd_pluginstance *upi)
{
	struct gprint_priv *op = (struct gprint_priv *) &upi->private;

	op->of = fopen(upi->config_kset->ces[0].u.string, "a");
	if (!op->of) {
		ulogd_log(ULOGD_FATAL, "can't open GPRINT log file: %s\n", 
			strerror(errno));
		return -1;
	}
	return 0;
}

static int gprint_fini(struct ulogd_pluginstance *pi)
{
	struct gprint_priv *op = (struct gprint_priv *) &pi->private;

	if (op->of != stdout)
		fclose(op->of);

	return 0;
}

static struct ulogd_plugin gprint_plugin = {
	.name = "GPRINT",
	.input = {
		.type = ULOGD_DTYPE_PACKET | ULOGD_DTYPE_FLOW | ULOGD_DTYPE_SUM,
	},
	.output = {
		.type = ULOGD_DTYPE_SINK,
	},
	.configure = &gprint_configure,
	.interp	= &gprint_interp,
	.start 	= &gprint_init,
	.stop	= &gprint_fini,
	.signal = &sighup_handler_print,
	.config_kset = &gprint_kset,
	.version = VERSION,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	ulogd_register_plugin(&gprint_plugin);
}
