/* ulogd_XML.c.
 *
 * ulogd output target for XML logging.
 *
 * (C) 2010 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 
 *  as published by the Free Software Foundation
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

#include <sys/types.h>
#include <inttypes.h>
#include "../config.h"
#ifdef BUILD_NFLOG
#include <libnetfilter_log/libnetfilter_log.h>
#endif
#ifdef BUILD_NFCT
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#endif
#ifdef BUILD_NFACCT
#include <libnetfilter_acct/libnetfilter_acct.h>
#endif
#include <ulogd/ulogd.h>
#include <sys/param.h>
#include <time.h>
#include <errno.h>

#ifndef ULOGD_XML_DEFAULT_DIR
#define ULOGD_XML_DEFAULT_DIR "/var/log/"
#endif

enum {
	KEY_CT,
	KEY_PCKT,
	KEY_SUM,
};

static struct ulogd_key xml_inp[] = {
	[KEY_CT] = {
                .type = ULOGD_RET_RAW,
                .flags = ULOGD_RETF_NONE | ULOGD_KEYF_OPTIONAL,
                .name = "ct",
	},
	[KEY_PCKT] = {
                .type = ULOGD_RET_RAW,
                .flags = ULOGD_RETF_NONE | ULOGD_KEYF_OPTIONAL,
                .name = "raw",
	},
	[KEY_SUM] = {
                .type = ULOGD_RET_RAW,
                .flags = ULOGD_RETF_NONE | ULOGD_KEYF_OPTIONAL,
                .name = "sum",
	},
};

enum {
	CFG_XML_DIR,
	CFG_XML_SYNC,
	CFG_XML_STDOUT,
};

static struct config_keyset xml_kset = {
	.num_ces = 3,
	.ces = {
		[CFG_XML_DIR] = {
			.key = "directory", 
			.type = CONFIG_TYPE_STRING, 
			.options = CONFIG_OPT_NONE,
			.u = { .string = ULOGD_XML_DEFAULT_DIR },
		},
		[CFG_XML_SYNC] = {
			.key = "sync",
			.type = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u = { .value = 0 },
		},
		[CFG_XML_STDOUT] = {
			.key = "stdout",
			.type = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u = { .value = 0 },
		},
	},
};

struct xml_priv {
        FILE *of;
};

static int
xml_output_flow(struct ulogd_key *inp, char *buf, ssize_t size)
{
#ifdef BUILD_NFCT
	struct nf_conntrack *ct = ikey_get_ptr(&inp[KEY_CT]);
	int tmp;

	tmp = nfct_snprintf(buf, size, ct, 0, NFCT_O_XML,
			    NFCT_OF_SHOW_LAYER3 | NFCT_OF_ID | NFCT_OF_TIME);
	if (tmp < 0 || tmp >= size)
		return -1;

	return 0;
#else
	return -1;
#endif
}

static int
xml_output_packet(struct ulogd_key *inp, char *buf, ssize_t size)
{
#ifdef BUILD_NFLOG
	struct nflog_data *ldata = ikey_get_ptr(&inp[KEY_PCKT]);
	int tmp;

	tmp = nflog_snprintf_xml(buf, size, ldata, NFLOG_XML_ALL);
	if (tmp < 0 || tmp >= size)
		return -1;

	return 0;
#else
	return -1;
#endif
}

static int
xml_output_sum(struct ulogd_key *inp, char *buf, ssize_t size)
{
#ifdef BUILD_NFACCT
	struct nfacct *nfacct = ikey_get_ptr(&inp[KEY_SUM]);
	int tmp;

	tmp = nfacct_snprintf(buf, size, nfacct, NFACCT_SNPRINTF_T_XML,
						 NFACCT_SNPRINTF_F_TIME);
	if (tmp < 0 || tmp >= size)
		return -1;
	return 0;
#else
	return -1;
#endif
}


static int xml_output(struct ulogd_pluginstance *upi)
{
	struct ulogd_key *inp = upi->input.keys;
	struct xml_priv *opi = (struct xml_priv *) &upi->private;
	static char buf[4096];
	int ret = -1;

	if (pp_is_valid(inp, KEY_CT))
		ret = xml_output_flow(inp, buf, sizeof(buf));
	else if (pp_is_valid(inp, KEY_PCKT))
		ret = xml_output_packet(inp, buf, sizeof(buf));
	else if (pp_is_valid(inp, KEY_SUM))
		ret = xml_output_sum(inp, buf, sizeof(buf));

	if (ret < 0)
		return ULOGD_IRET_ERR;

	fprintf(opi->of, "%s\n", buf);
	if (upi->config_kset->ces[CFG_XML_SYNC].u.value != 0)
		fflush(opi->of);

	return ULOGD_IRET_OK;
}

static int xml_configure(struct ulogd_pluginstance *upi,
			 struct ulogd_pluginstance_stack *stack)
{
	int ret;

	ret = config_parse_file(upi->id, upi->config_kset);
	if (ret < 0)
		return ret;

	return 0;
}

static int xml_fini(struct ulogd_pluginstance *pi)
{
	struct xml_priv *op = (struct xml_priv *) &pi->private;
	/* XXX: provide generic function to get the input plugin. */
	struct ulogd_pluginstance *input_plugin =
		llist_entry(pi->stack->list.next,
			    struct ulogd_pluginstance, list);

	/* the initial tag depends on the source. */
	if (input_plugin->plugin->output.type & ULOGD_DTYPE_FLOW)
		fprintf(op->of, "</conntrack>\n");
	else if (input_plugin->plugin->output.type & ULOGD_DTYPE_RAW)
		fprintf(op->of, "</packet>\n");
	else if (input_plugin->plugin->output.type & ULOGD_DTYPE_SUM)
		fprintf(op->of, "</sum>\n");

	if (op->of != stdout)
		fclose(op->of);

	return 0;
}

static int xml_open_file(struct ulogd_pluginstance *upi)
{
	time_t now;
	struct tm *tm;
	char buf[PATH_MAX], filename[FILENAME_MAX];
	struct xml_priv *op = (struct xml_priv *) &upi->private;
	int ret;

	struct ulogd_pluginstance *input_plugin =
		llist_entry(upi->stack->list.next,
			    struct ulogd_pluginstance, list);
	char file_infix[strlen("flow")+1];

	if (input_plugin->plugin->output.type & ULOGD_DTYPE_FLOW)
		strcpy(file_infix, "flow");
        else if (input_plugin->plugin->output.type & ULOGD_DTYPE_RAW)
		strcpy(file_infix, "pkt");
        else if (input_plugin->plugin->output.type & ULOGD_DTYPE_SUM)
		strcpy(file_infix, "sum");

	now = time(NULL);
	tm = localtime(&now);
	ret = snprintf(filename, sizeof(filename),
		       "ulogd-%s-%.2d%.2d%.4d-%.2d%.2d%.2d.xml",
		       file_infix, 
		       tm->tm_mday, tm->tm_mon + 1, 1900 + tm->tm_year,
		       tm->tm_hour, tm->tm_min, tm->tm_sec);

	if (ret == -1 || ret >= (int)sizeof(filename))
		return -1;

	ret = snprintf(buf, sizeof(buf), "%s/%s",
		       upi->config_kset->ces[CFG_XML_DIR].u.string,
		       filename);
	if (ret == -1 || ret >= (int)sizeof(buf))
		return -1;

	op->of = fopen(buf, "a");
	if (!op->of)
		return -1;

	return 0;
}

static void xml_print_header(struct ulogd_pluginstance *upi)
{
	struct xml_priv *op = (struct xml_priv *) &upi->private;

	fprintf(op->of, "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");

	struct ulogd_pluginstance *input_plugin =
		llist_entry(upi->stack->list.next,
			    struct ulogd_pluginstance, list);

	if (input_plugin->plugin->output.type & ULOGD_DTYPE_FLOW)
		fprintf(op->of, "<conntrack>\n");
	else if (input_plugin->plugin->output.type & ULOGD_DTYPE_RAW)
		fprintf(op->of, "<packet>\n");
	else if (input_plugin->plugin->output.type & ULOGD_DTYPE_SUM)
		fprintf(op->of, "<sum>\n");

	if (upi->config_kset->ces[CFG_XML_SYNC].u.value != 0)
		fflush(op->of);
}

static int xml_start(struct ulogd_pluginstance *upi)
{
	struct xml_priv *op = (struct xml_priv *) &upi->private;

	if (upi->config_kset->ces[CFG_XML_STDOUT].u.value != 0) {
		op->of = stdout;
	} else {
		if (xml_open_file(upi) < 0) {
			ulogd_log(ULOGD_FATAL, "can't open XML file: %s\n", 
				  strerror(errno));
			return -1;
		}
	}
	xml_print_header(upi);
	return 0;
}

static void
xml_signal_handler(struct ulogd_pluginstance *upi, int signal)
{
	switch (signal) {
	case SIGHUP:
		ulogd_log(ULOGD_NOTICE, "XML: reopening logfile\n");
		xml_fini(upi);
		if (xml_open_file(upi) < 0) {
			ulogd_log(ULOGD_FATAL, "can't open XML file: %s\n", 
				  strerror(errno));
			return;
		}
		xml_print_header(upi);
		break;
	default:
		break;
	}
}

static struct ulogd_plugin xml_plugin = {
	.name = "XML",
	.input = {
		.keys = xml_inp,
		.num_keys = ARRAY_SIZE(xml_inp),
		.type = ULOGD_DTYPE_FLOW | ULOGD_DTYPE_SUM,
	},
	.output = {
		.type = ULOGD_DTYPE_SINK,
	},
	.config_kset	= &xml_kset,
	.priv_size	= sizeof(struct xml_priv),
	
	.configure	= &xml_configure,
	.start		= &xml_start,
	.stop		= &xml_fini,
	.interp		= &xml_output,
	.signal		= &xml_signal_handler,
	.version	= VERSION,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	ulogd_register_plugin(&xml_plugin);
}
