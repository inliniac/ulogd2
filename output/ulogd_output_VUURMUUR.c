/* ulogd_VUURMUUR.c
 *
 * ulogd output target for logging to a file in comma-separated key-value.
 * This is a generalization of ulogd_VUURMUUR.c
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
#include <vuurmuur.h>
#include <ulogd/ulogd.h>
#include <ulogd/conffile.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif


#ifndef ULOGD_VUURMUUR_DEFAULT
#define ULOGD_VUURMUUR_DEFAULT	"/var/log/ulogd.vuurmuur"
#endif

const char *version = "0.8rc1";
struct vrmr_hash_table zone_htbl;
struct vrmr_hash_table service_htbl;

struct vuurmuur_priv {
	FILE *of;
};

enum vuurmuur_conf {
	VUURMUUR_CONF_FILENAME = 0,
	VUURMUUR_CONF_SYNC,
	VUURMUUR_CONF_TIMESTAMP,
	VUURMUUR_CONF_MAX
};

static struct config_keyset vuurmuur_kset = {
	.num_ces = VUURMUUR_CONF_MAX,
	.ces = {
		[VUURMUUR_CONF_FILENAME] = {
			.key = "file",
			.type = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_NONE,
			.u = {.string = ULOGD_VUURMUUR_DEFAULT },
		},
		[VUURMUUR_CONF_SYNC] = {
			.key = "sync",
			.type = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u = { .value = 0 },
		},
		[VUURMUUR_CONF_TIMESTAMP] = {
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

static int vuurmuur_interp(struct ulogd_pluginstance *upi)
{
	struct vuurmuur_priv *opi = (struct vuurmuur_priv *) &upi->private;
	unsigned int i;
	char buf[4096];
    struct vrmr_log_record vr;

    memset(&vr, 0x00, sizeof(vr));

	if (upi->config_kset->ces[VUURMUUR_CONF_TIMESTAMP].u.value != 0) {
		struct tm tm;
		time_t now;

		now = time(NULL);
		localtime_r(&now, &tm);

        char    s[256];
        strftime (s, sizeof(s), "%b %d %T", &tm);
        if (sscanf (s, "%3s %2d %2d:%2d:%2d", vr.month, &vr.day,
                    &vr.hour, &vr.minute, &vr.second) != 5)
			return ULOGD_IRET_OK;
	}

	for (i = 0; i < upi->input.num_keys; i++) {
		struct ulogd_key *key = upi->input.keys[i].u.source;
		if (!key || !IS_VALID(*key))
			continue;

		switch (key->type) {
		case ULOGD_RET_STRING:
            if (strcmp(key->name, "oob.prefix") == 0) {
                vrmr_log_record_parse_prefix(&vr, (char *) key->u.value.ptr);
            } else if (strcmp(key->name, "oob.in") == 0) {
                if (strlen((char *) key->u.value.ptr) > 0)
                    snprintf(vr.from_int, sizeof(vr.from_int), "in: %s ", (char *) key->u.value.ptr);
            } else if (strcmp(key->name, "oob.out") == 0) {
                if (strlen((char *) key->u.value.ptr) > 0)
                    snprintf(vr.to_int, sizeof(vr.to_int), "out: %s ", (char *) key->u.value.ptr);
            } else if (strcmp(key->name, "ip.daddr.str") == 0) {
                strlcpy(vr.dst_ip, (char *) key->u.value.ptr, sizeof(vr.dst_ip));
            } else if (strcmp(key->name, "ip.saddr.str") == 0) {
                strlcpy(vr.src_ip, (char *) key->u.value.ptr, sizeof(vr.src_ip));
            } else {
                vrmr_debug("ULOGD_RET_STRING", "key %s, %d, %s", key->name, key->type, (char *) key->u.value.ptr);
            }
            break;
		case ULOGD_RET_BOOL:
		case ULOGD_RET_INT8:
		case ULOGD_RET_INT16:
		case ULOGD_RET_INT32:
            if (strcmp(key->name, "tcp.syn") == 0)
                vr.syn = (int)key->u.value.i8;
            else if (strcmp(key->name, "tcp.ack") == 0)
                vr.ack = (int)key->u.value.i8;
            else if (strcmp(key->name, "tcp.fin") == 0)
                vr.fin = (int)key->u.value.i8;
            else if (strcmp(key->name, "tcp.rst") == 0)
                vr.rst = (int)key->u.value.i8;
            else if (strcmp(key->name, "tcp.psh") == 0)
                vr.psh = (int)key->u.value.i8;
            else if (strcmp(key->name, "tcp.urg") == 0)
                vr.urg = (int)key->u.value.i8;
            else
                vrmr_debug("ULOGD_RET_BOOL/INT", "key %s, %d", key->name, key->type);
			break;
		case ULOGD_RET_UINT8:
		case ULOGD_RET_UINT16:
		case ULOGD_RET_UINT32:
		case ULOGD_RET_UINT64:
        {
            if (strcmp(key->name, "oob.family") == 0) {
                vr.ipv6 = (key->u.value.ui8 == 10);
            } else if (strcmp(key->name, "ip.totlen") == 0) {
                vr.packet_len = (unsigned int) key->u.value.ui16;
            } else if (strcmp(key->name, "ip6.payloadlen") == 0) {
                vr.packet_len = (unsigned int) key->u.value.ui16 + 40;
            } else if (strcmp(key->name, "ip.ttl") == 0 ||
                       strcmp(key->name, "ip6.hoplimit") == 0) {
                vr.ttl = (unsigned int) key->u.value.ui8;
            } else if (strcmp(key->name, "ip.protocol") == 0) {
                vr.protocol = (int) key->u.value.ui8;
            } else if (strcmp(key->name, "tcp.sport") == 0 ||
                       strcmp(key->name, "udp.sport") == 0) {
                vr.src_port = (int) key->u.value.ui16;
            } else if (strcmp(key->name, "tcp.dport") == 0 ||
                       strcmp(key->name, "udp.dport") == 0) {
                vr.dst_port = (int) key->u.value.ui16;
            } else if (strcmp(key->name, "icmp.type") == 0) {
                vr.icmp_type = (unsigned int) key->u.value.ui8;
            } else if (strcmp(key->name, "icmp.code") == 0) {
                vr.icmp_code = (unsigned int) key->u.value.ui8;
            } else
                vrmr_debug("ULOGD_RET_UINT", "key %s, %d", key->name, key->type);
			break;
        }
		case ULOGD_RET_IPADDR:
        {
            vrmr_debug("ULOGD_RET_IPADDR", "key %s, %d", key->name, key->type);
			break;
        }
		default:
            vrmr_debug("default", "key->name %s", key->name);
			/* don't know how to interpret this key. */
			break;
		}
	}

    /* ignore 127.* traffic */
    if (strncmp("127.", vr.dst_ip, 4) == 0 || strncmp("127.", vr.src_ip, 4) == 0)
        return ULOGD_IRET_OK;

    vrmr_log_record_get_names(0, &vr, &zone_htbl, &service_htbl);
    vrmr_log_record_build_line(0, &vr, buf, sizeof(buf));
    fprintf(opi->of, "%s", buf);

	if (upi->config_kset->ces[VUURMUUR_CONF_SYNC].u.value != 0)
		fflush(opi->of);

	return ULOGD_IRET_OK;
}

static void sighup_handler_print(struct ulogd_pluginstance *upi, int signal)
{
	struct vuurmuur_priv *oi = (struct vuurmuur_priv *) &upi->private;
	FILE *old = oi->of;

	switch (signal) {
	case SIGHUP:
		ulogd_log(ULOGD_NOTICE, "VUURMUUR: reopening logfile\n");
		oi->of = fopen(upi->config_kset->ces[0].u.string, "a");
		if (!oi->of) {
			ulogd_log(ULOGD_ERROR, "can't open VUURMUUR "
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

static int vuurmuur_configure(struct ulogd_pluginstance *upi,
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

static int vuurmuur_init(struct ulogd_pluginstance *upi)
{
	struct vuurmuur_priv *op = (struct vuurmuur_priv *) &upi->private;

	op->of = fopen(upi->config_kset->ces[0].u.string, "a");
	if (!op->of) {
		ulogd_log(ULOGD_FATAL, "can't open VUURMUUR log file: %s\n",
			strerror(errno));
		return -1;
	}

    struct vrmr_ctx vctx;
    int debuglvl = 0;

    vrmr_init(&vctx, "ulogd");
    vrmr_load(debuglvl, &vctx);

    vrmr_info("Info", "This is Ulogd2-Vuurmuur plugin %s", version);
    vrmr_info("Info", "Copyright (C) 2002-2013 by Victor Julien");

    vrmr_create_log_hash(debuglvl, &vctx, &service_htbl, &zone_htbl);

    vrmr_info("Info", "Vuurmuur init complete");
	return 0;
}

static int vuurmuur_fini(struct ulogd_pluginstance *pi)
{
	struct vuurmuur_priv *op = (struct vuurmuur_priv *) &pi->private;

	if (op->of != stdout)
		fclose(op->of);

	return 0;
}

static struct ulogd_plugin vuurmuur_plugin = {
	.name = "VUURMUUR",
	.input = {
		.type = ULOGD_DTYPE_PACKET | ULOGD_DTYPE_FLOW | ULOGD_DTYPE_SUM,
	},
	.output = {
		.type = ULOGD_DTYPE_SINK,
	},
	.configure = &vuurmuur_configure,
	.interp	= &vuurmuur_interp,
	.start	= &vuurmuur_init,
	.stop	= &vuurmuur_fini,
	.signal = &sighup_handler_print,
	.config_kset = &vuurmuur_kset,
	.version = VERSION,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	ulogd_register_plugin(&vuurmuur_plugin);
}
