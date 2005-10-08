/* ulogd_PCAP.c, Version $Revision$
 *
 * ulogd output target for writing pcap-style files (like tcpdump)
 *
 * FIXME: descr.
 * 
 *
 * (C) 2002 by Harald Welte <laforge@gnumonks.org>
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
 *
 * $Id$
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <pcap.h>
#include <ulogd/ulogd.h>
#include <ulogd/conffile.h>

#ifndef ULOGD_PCAP_DEFAULT
#define ULOGD_PCAP_DEFAULT	"/var/log/ulogd.pcap"
#endif

#ifndef ULOGD_PCAP_SYNC_DEFAULT
#define ULOGD_PCAP_SYNC_DEFAULT	0
#endif

#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[3]

static struct config_keyset pcap_kset = {
	.num_ces = 2,
	.ces = {
		{ 
			.key = "file", 
			.type = CONFIG_TYPE_STRING, 
			.options = CONFIG_OPT_NONE,
			.u.string = ULOGD_PCAP_DEFAULT,
		},
		{ 
			.key = "sync", 
			.type = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = ULOGD_PCAP_SYNC_DEFAULT,
		},
	},
};

static struct pcap_instance {
	FILE *of;
};

struct intr_id {
	char* name;
	unsigned int id;		
};

#define INTR_IDS 	5
static struct ulogd_key pcap_keys[INTR_IDS] = {
	{ .name = "raw.pkt" },
	{ .name = "raw.pktlen" },
	{ .name = "ip.totlen" },
	{ .name = "oob.time.sec" },
	{ .name = "oob.time.usec" },
};

#define GET_VALUE(res, x)	(res[x].u.source->u.value)
#define GET_FLAGS(res, x)	(res[x].u.source->flags)

static int pcap_output(struct ulogd_pluginstance *upi)
{
	struct pcap_instance *pi = (struct pcap_instance *) &upi->private;
	struct ulogd_key *res = upi->input;
	struct pcap_pkthdr pchdr;

	pchdr.caplen = GET_VALUE(res, 1).ui32;
	pchdr.len = GET_VALUE(res, 2).ui32;

	if (GET_FLAGS(res, 3) & ULOGD_RETF_VALID
	    && GET_FLAGS(res, 4) & ULOGD_RETF_VALID) {
		pchdr.ts.tv_sec = GET_VALUE(res, 3).ui32;
		pchdr.ts.tv_usec = GET_VALUE(res, 4).ui32;
	} else {
		/* use current system time */
		gettimeofday(&pchdr.ts, NULL);
	}

	if (fwrite(&pchdr, sizeof(pchdr), 1, pi->of) != 1) {
		ulogd_log(ULOGD_ERROR, "Error during write: %s\n",
			  strerror(errno));
		return 1;
	}
	if (fwrite(GET_VALUE(res, 0).ptr, pchdr.caplen, 1, pi->of) != 1) {
		ulogd_log(ULOGD_ERROR, "Error during write: %s\n",
			  strerror(errno));
		return 1;
	}

	if (upi->config_kset->ces[1].u.value)
		fflush(of);

	return 0;
}

/* stolen from libpcap savefile.c */
#define LINKTYPE_RAW            101
#define TCPDUMP_MAGIC	0xa1b2c3d4

static int write_pcap_header(struct pcap_instance *pi)
{
	struct pcap_file_header pcfh;
	int ret;

	pcfh.magic = TCPDUMP_MAGIC;
	pcfh.version_major = PCAP_VERSION_MAJOR;
	pcfh.version_minor = PCAP_VERSION_MINOR;
	pcfh.thiszone = timezone;
	pcfh.sigfigs = 0;
	pcfh.snaplen = 64 * 1024; /* we don't know the length in advance */
	pcfh.linktype = LINKTYPE_RAW;

	ret =  fwrite(&pcfh, sizeof(pcfh), 1, pi->of);
	fflush(pi->of);

	return ret;
}

static int append_create_outfile(struct ulogd_pluginstance *upi)
{
	struct pcap_instance *pi = (struct pcap_instance *) &upi->private;
	char *filename = upi->config_kset->ces[0].u.string;
	struct stat st_dummy;
	int exist = 0;

	if (stat(filename, &st_dummy) == 0 && st_dummy.st_size > 0)
		exist = 1;

	if (!exist) {
		of = fopen(filename, "w");
		if (!of) {
			ulogd_log(ULOGD_ERROR, "can't open pcap file: %s\n",
				  strerror(errno));
			return -1;
		}
		if (!write_pcap_header()) {
			ulogd_log(ULOGD_ERROR, "can't write pcap header: %s\n",
				  strerror(errno));
			return -1;
		}
	} else {
		of = fopen(filename, "a");
		if (!of) {
			ulogd_log(ULOGD_ERROR, "can't open pcap file: %s\n", 
				strerror(errno));
			return -1;
		}		
	}

	return 0;
}

static void pcap_signal_handler(struct ulogd_pluginstance *upi, int signal)
{
	struct pcap_instance *pi = (struct pcap_instance *) &upi->private;

	switch (signal) {
	case SIGHUP:
		ulogd_log(ULOGD_NOTICE, "reopening capture file\n");
		fclose(pi->of);
		append_create_outfile(upi);
		break;
	default:
		break;
	}
}

static int configure_pcap(struct ulogd_pluginstance *upi,
			  struct ulogd_pluginstance_stack *stack)
{
	return config_parse_file(upi->id, upi->config_kset);
}

static int start_pcap(struct ulogd_pluginstance *upi)
{
	return append_create_outfile(upi);
}

static int stop_pcap(struct ulogd_pluginstance *upi)
{
	struct pcap_instance *pi = (struct pcap_instance *) &upi->private;

	if (pi->of)
		fclose(pi->of);

	return 0;
}

static struct ulogd_plugin pcap_plugin = {
	.name = "PCAP",
	.input = {
		.keys = pcap_keys,
		.num_keys = ARRAY_SIZE(pcap_keys),
		.type = ULOGD_DTYPE_PACKET,
	},
	.output = {
		.type = ULOGD_DTYPE_SINK,
	},
	.config_kset	= &pcap_kset,
	.priv_size	= sizeof(struct pcap_instance),

	.configure	= &configure_pcap,
	.start		= &start_pcap,
	.stop		= &stop_pcap,
	.signal		= &signal_pcap,
	.interp		= &interp_pcap,
};

static ulog_output_t pcap_op = {
	.name = "pcap", 
	.init = &pcap_init,
	.fini = &pcap_fini,
	.output = &pcap_output,
	.signal = &pcap_signal_handler,
};

void __attribute__ ((constructor)) init(void);

void init(void)
{
	ulogd_register_plugin(&pcap_plugin);
}
