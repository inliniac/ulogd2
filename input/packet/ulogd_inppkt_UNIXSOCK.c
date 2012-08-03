/*
 * UNIXSOCK input module for ulogd
 *
 * Copyright(C) 2008-2010 INL
 * Written by  Pierre Chifflier <chifflier@edenwall.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2·
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include <unistd.h>
#include <stdlib.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>

#include <ulogd/ulogd.h>

/* Default size of the receive buffer for the unix socket
   0 means that ulogd will use getsockopt(SO_RCVBUF) to determine it
   at runtime */
#define UNIXSOCK_BUFSIZE_DEFAULT	0

#define UNIXSOCK_PERMS_DEFAULT		0600

#define UNIXSOCK_UNIXPATH_DEFAULT	"/var/run/ulogd/ulogd2.sock"

#define ULOGD_SOCKET_MARK	0x41c90fd4

struct unixsock_input {
	char *path;
	char *unixsock_buf;
	unsigned int unixsock_perms;
	unsigned int unixsock_buf_avail;
	unsigned int unixsock_buf_size;
	struct ulogd_fd unixsock_server_fd;
	struct ulogd_fd unixsock_instance_fd;
};

enum nflog_keys {
	UNIXSOCK_KEY_RAW_MAC = 0,
	UNIXSOCK_KEY_RAW_PCKT,
	UNIXSOCK_KEY_RAW_PCKTLEN,
	UNIXSOCK_KEY_RAW_PCKTCOUNT,
	UNIXSOCK_KEY_OOB_PREFIX,
	UNIXSOCK_KEY_OOB_TIME_SEC,
	UNIXSOCK_KEY_OOB_TIME_USEC,
	UNIXSOCK_KEY_OOB_MARK,
	UNIXSOCK_KEY_OOB_IN,
	UNIXSOCK_KEY_OOB_OUT,
	UNIXSOCK_KEY_OOB_HOOK,
	UNIXSOCK_KEY_RAW_MAC_LEN,
	UNIXSOCK_KEY_OOB_SEQ_LOCAL,
	UNIXSOCK_KEY_OOB_SEQ_GLOBAL,
	UNIXSOCK_KEY_OOB_FAMILY,
	UNIXSOCK_KEY_OOB_PROTOCOL,
	UNIXSOCK_KEY_OOB_UID,
	UNIXSOCK_KEY_OOB_GID,
	UNIXSOCK_KEY_RAW_LABEL,
	UNIXSOCK_KEY_RAW_TYPE,
	UNIXSOCK_KEY_RAW_MAC_SADDR,
	UNIXSOCK_KEY_RAW_MAC_ADDRLEN,
	UNIXSOCK_KEY_NUFW_USER_NAME,
	UNIXSOCK_KEY_NUFW_USER_ID,
	UNIXSOCK_KEY_NUFW_OS_NAME,
	UNIXSOCK_KEY_NUFW_OS_REL,
	UNIXSOCK_KEY_NUFW_OS_VERS,
	UNIXSOCK_KEY_NUFW_APP_NAME,
	/* Add new keys after this line */
};

static struct ulogd_key output_keys[] = {
	[UNIXSOCK_KEY_RAW_MAC] = {
		.type = ULOGD_RET_RAW,
		.flags = ULOGD_RETF_NONE,
		.name = "raw.mac",
	},
	[UNIXSOCK_KEY_RAW_MAC_SADDR] = {
		.type = ULOGD_RET_RAW,
		.flags = ULOGD_RETF_NONE,
		.name = "raw.mac.saddr",
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_sourceMacAddress,
		},
	},
	[UNIXSOCK_KEY_RAW_PCKT] = {
		.type = ULOGD_RET_RAW,
		.flags = ULOGD_RETF_NONE,
		.name = "raw.pkt",
		.ipfix = {
			.vendor = IPFIX_VENDOR_NETFILTER,
			.field_id = IPFIX_NF_rawpacket,
		},
	},
	[UNIXSOCK_KEY_RAW_PCKTLEN] = {
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "raw.pktlen",
		.ipfix = {
			.vendor = IPFIX_VENDOR_NETFILTER,
			.field_id = IPFIX_NF_rawpacket_length,
		},
	},
	[UNIXSOCK_KEY_RAW_PCKTCOUNT] = {
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "raw.pktcount",
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_packetDeltaCount,
		},
	},
	[UNIXSOCK_KEY_OOB_PREFIX] = {
		.type = ULOGD_RET_STRING,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.prefix",
		.ipfix = {
			.vendor = IPFIX_VENDOR_NETFILTER,
			.field_id = IPFIX_NF_prefix,
		},
	},
	[UNIXSOCK_KEY_OOB_TIME_SEC] = {
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.time.sec",
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_flowStartSeconds,
		},
	},
	[UNIXSOCK_KEY_OOB_TIME_USEC] = {
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.time.usec",
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_flowStartMicroSeconds,
		},
	},
	[UNIXSOCK_KEY_OOB_MARK] = {
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.mark",
		.ipfix = {
			.vendor = IPFIX_VENDOR_NETFILTER,
			.field_id = IPFIX_NF_mark,
		},
	},
	[UNIXSOCK_KEY_OOB_IN] = {
		.type = ULOGD_RET_STRING,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.in",
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_ingressInterface,
		},
	},
	[UNIXSOCK_KEY_OOB_OUT] = {
		.type = ULOGD_RET_STRING,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.out",
		.ipfix = {
			.vendor = IPFIX_VENDOR_IETF,
			.field_id = IPFIX_egressInterface,
		},
	},
	[UNIXSOCK_KEY_OOB_HOOK] = {
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.hook",
		.ipfix = {
			.vendor = IPFIX_VENDOR_NETFILTER,
			.field_id = IPFIX_NF_hook,
		},
	},
	[UNIXSOCK_KEY_RAW_MAC_LEN] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "raw.mac_len",
	},
	[UNIXSOCK_KEY_RAW_MAC_ADDRLEN] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "raw.mac.addrlen",
	},

	[UNIXSOCK_KEY_OOB_SEQ_LOCAL] = {
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.seq.local",
		.ipfix = {
			.vendor = IPFIX_VENDOR_NETFILTER,
			.field_id = IPFIX_NF_seq_local,
		},
	},
	[UNIXSOCK_KEY_OOB_SEQ_GLOBAL] = {
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.seq.global",
		.ipfix = {
			.vendor = IPFIX_VENDOR_NETFILTER,
			.field_id = IPFIX_NF_seq_global,
		},
	},
	[UNIXSOCK_KEY_OOB_FAMILY] = {
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.family",
	},
	[UNIXSOCK_KEY_OOB_PROTOCOL] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.protocol",
	},
	[UNIXSOCK_KEY_OOB_UID] = {
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.uid",
	},
	[UNIXSOCK_KEY_OOB_GID] = {
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "oob.gid",
	},
	[UNIXSOCK_KEY_RAW_LABEL] = {
		.type = ULOGD_RET_UINT8,
		.flags = ULOGD_RETF_NONE,
		.name = "raw.label",
	},
	[UNIXSOCK_KEY_RAW_TYPE] = {
		.type = ULOGD_RET_UINT16,
		.flags = ULOGD_RETF_NONE,
		.name = "raw.type",
	},
	[UNIXSOCK_KEY_NUFW_USER_NAME] = {
		.type = ULOGD_RET_STRING,
		.flags = ULOGD_RETF_NONE,
		.name = "nufw.user.name",
	},
	[UNIXSOCK_KEY_NUFW_USER_ID] = {
		.type = ULOGD_RET_UINT32,
		.flags = ULOGD_RETF_NONE,
		.name = "nufw.user.id",
	},
	[UNIXSOCK_KEY_NUFW_OS_NAME] = {
		.type = ULOGD_RET_STRING,
		.flags = ULOGD_RETF_NONE,
		.name = "nufw.os.name",
	},
	[UNIXSOCK_KEY_NUFW_OS_REL] = {
		.type = ULOGD_RET_STRING,
		.flags = ULOGD_RETF_NONE,
		.name = "nufw.os.rel",
	},
	[UNIXSOCK_KEY_NUFW_OS_VERS] = {
		.type = ULOGD_RET_STRING,
		.flags = ULOGD_RETF_NONE,
		.name = "nufw.os.vers",
	},
	[UNIXSOCK_KEY_NUFW_APP_NAME] = {
		.type = ULOGD_RET_STRING,
		.flags = ULOGD_RETF_NONE,
		.name = "nufw.app.name",
	},
};

static struct config_keyset libunixsock_kset = {
	.num_ces = 5,
	.ces = {
		{
			.key 	 = "socket_path",
			.type 	 = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_NONE,
			.u.string = UNIXSOCK_UNIXPATH_DEFAULT,
		},
		{
			.key 	 = "bufsize",
			.type 	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = UNIXSOCK_BUFSIZE_DEFAULT,
		},
		{
			.key 	 = "perms",
			.type 	 = CONFIG_TYPE_INT,
			.options = CONFIG_OPT_NONE,
			.u.value = UNIXSOCK_PERMS_DEFAULT,
		},
		{
			.key 	 = "owner",
			.type 	 = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_NONE,
		},
		{
			.key 	 = "group",
			.type 	 = CONFIG_TYPE_STRING,
			.options = CONFIG_OPT_NONE,
		},
	},
};

enum {
	UNIXSOCK_OPT_UNIXPATH = 0,
	UNIXSOCK_OPT_BUFSIZE,
	UNIXSOCK_OPT_PERM,
	UNIXSOCK_OPT_OWNER,
	UNIXSOCK_OPT_GROUP,
};

#define unixpath_ce(x)		((x)->ces[UNIXSOCK_OPT_UNIXPATH])
#define bufsize_ce(x)		((x)->ces[UNIXSOCK_OPT_BUFSIZE])
#define perms_ce(x)		((x)->ces[UNIXSOCK_OPT_PERM])
#define owner_ce(x)		((x)->ces[UNIXSOCK_OPT_OWNER])
#define group_ce(x)		((x)->ces[UNIXSOCK_OPT_GROUP])

enum ulogd2_option_type {
	ULOGD2_OPT_UNUSED = 0,
	ULOGD2_OPT_PREFIX,	/* log prefix (string) */
	ULOGD2_OPT_OOB_IN,	/* input device (string) */
	ULOGD2_OPT_OOB_OUT,	/* output device (string) */
	ULOGD2_OPT_OOB_TIME_SEC,	/* packet arrival time (u_int32_t) */

	ULOGD2_OPT_USER=200,	/* user name (string) */
	ULOGD2_OPT_USERID,	/* user id (u_int32_t) */
	ULOGD2_OPT_OSNAME,	/* OS name (string) */
	ULOGD2_OPT_OSREL,	/* OS release (string) */
	ULOGD2_OPT_OSVERS,	/* OS version (string) */
	ULOGD2_OPT_APPNAME,	/* application name (string) */
	ULOGD2_OPT_STATE,	/* connection state: 0 (drop), 1 (open), 2 (established), 3 (close), 4 (unknown) */

	/* Add new options after this line */
};

struct ulogd_unixsock_packet_t {
	uint32_t marker;
	uint16_t total_size;
	uint32_t version:4,
		 reserved:28;
	uint16_t payload_length;
	struct iphdr payload;
} __attribute__((packed));

struct ulogd_unixsock_option_t  {
	uint32_t option_id;
	uint32_t option_length;
	char     option_value[0];
} __attribute__((packed));

#define USOCK_ALIGNTO 8
#define USOCK_ALIGN(len) ( ((len)+USOCK_ALIGNTO-1) & ~(USOCK_ALIGNTO-1) )

static int handle_packet(struct ulogd_pluginstance *upi, struct ulogd_unixsock_packet_t *pkt, u_int16_t total_len)
{
	char *data = NULL;
	struct iphdr *ip;
	struct ulogd_key *ret = upi->output.keys;
	u_int8_t oob_family;
	u_int16_t payload_len;
	u_int32_t option_number;
	u_int32_t option_length;
	char *buf;
	struct ulogd_unixsock_option_t *option;
	int new_offset;
	char *options_start;

	ulogd_log(ULOGD_DEBUG,
			"ulogd2: handling packet\n");

	payload_len = ntohs(pkt->payload_length);

	ip = &pkt->payload;
	if (ip->version == 4)
		oob_family = AF_INET;
	else if (ip->version == 6)
		oob_family = AF_INET6;
	else oob_family = 0;

	okey_set_u8(&ret[UNIXSOCK_KEY_OOB_FAMILY], oob_family);
	okey_set_ptr(&ret[UNIXSOCK_KEY_RAW_PCKT], ip);
	okey_set_u32(&ret[UNIXSOCK_KEY_RAW_PCKTLEN], payload_len);

	/* options */
	if (total_len > payload_len + sizeof(u_int16_t)) {
		/* option starts at the next aligned address after the payload */
		new_offset = USOCK_ALIGN(payload_len);
		options_start = (void*)ip + new_offset;
		data = options_start;
		total_len -= (options_start - (char*)pkt);

		while ( (data - options_start) < total_len) {

			option = (void*)data;
			option_number = ntohl(option->option_id);
			option_length = ntohl(option->option_length);
			buf = option->option_value;

			/* next option is also aligned */
			new_offset = USOCK_ALIGN(option_length);
			data += sizeof(option->option_id) + sizeof(option->option_length) + new_offset;

			ulogd_log(ULOGD_DEBUG,
					"ulogd2: option %d (len %d) `%s'\n",
					option_number, option_length, buf);

			switch(option_number) {
			case ULOGD2_OPT_PREFIX:
				okey_set_ptr(&ret[UNIXSOCK_KEY_OOB_PREFIX], buf);
				break;
			case ULOGD2_OPT_OOB_IN:
				okey_set_ptr(&ret[UNIXSOCK_KEY_OOB_IN], buf);
				break;
			case ULOGD2_OPT_OOB_OUT:
				okey_set_ptr(&ret[UNIXSOCK_KEY_OOB_OUT], buf);
				break;
			case ULOGD2_OPT_OOB_TIME_SEC:
				okey_set_u32(&ret[UNIXSOCK_KEY_OOB_TIME_SEC], *(u_int32_t*)buf);
				break;
			case ULOGD2_OPT_USER:
				okey_set_ptr(&ret[UNIXSOCK_KEY_NUFW_USER_NAME], buf);
				break;
			case ULOGD2_OPT_USERID:
				okey_set_u32(&ret[UNIXSOCK_KEY_NUFW_USER_ID], *(u_int32_t*)buf);
				break;
			case ULOGD2_OPT_OSNAME:
				okey_set_ptr(&ret[UNIXSOCK_KEY_NUFW_OS_NAME], buf);
				break;
			case ULOGD2_OPT_OSREL:
				okey_set_ptr(&ret[UNIXSOCK_KEY_NUFW_OS_REL], buf);
				break;
			case ULOGD2_OPT_OSVERS:
				okey_set_ptr(&ret[UNIXSOCK_KEY_NUFW_OS_VERS], buf);
				break;
			case ULOGD2_OPT_APPNAME:
				okey_set_ptr(&ret[UNIXSOCK_KEY_NUFW_APP_NAME], buf);
				break;
			case ULOGD2_OPT_STATE:
				okey_set_u8(&ret[UNIXSOCK_KEY_RAW_LABEL], *(u_int8_t*)buf);
				break;
			default:
				ulogd_log(ULOGD_NOTICE,
						"ulogd2: unknown option %d\n",
						option_number);
				break;
			};
		}
	}

	/* number of packets */
	okey_set_u32(&ret[UNIXSOCK_KEY_RAW_PCKTCOUNT], 1);

	ulogd_propagate_results(upi);

	return 0;
}

static int _create_unix_socket(const char *unix_path)
{
	int ret = -1;
	struct sockaddr_un server_sock;
	int s;
	struct stat st_dummy;

	s = socket(AF_UNIX, SOCK_STREAM, 0);
	if (s < 0) {
		ulogd_log(ULOGD_ERROR,
				"ulogd2: could not create unix socket\n");
		return -1;
	}

	server_sock.sun_family = AF_UNIX;
	strncpy(server_sock.sun_path, unix_path, sizeof(server_sock.sun_path));
	server_sock.sun_path[sizeof(server_sock.sun_path)-1] = '\0';

	if (stat(unix_path, &st_dummy) == 0 && st_dummy.st_size > 0) {
		ulogd_log(ULOGD_ERROR,
				"ulogd2: unix socket \'%s\' already exists\n",
				unix_path);
		close(s);
		return -1;
	}

	ret = bind(s, (struct sockaddr *)&server_sock, sizeof(server_sock));
	if (ret < 0) {
		ulogd_log(ULOGD_ERROR,
				"ulogd2: could not bind to unix socket \'%s\'\n",
				server_sock.sun_path);
		close(s);
		return -1;
	}

	ret = listen(s, 10);
	if (ret < 0) {
		ulogd_log(ULOGD_ERROR,
				"ulogd2: could not bind to unix socket \'%s\'\n",
				server_sock.sun_path);
		close(s);
		return -1;
	}

	return s;
}

static int _unix_socket_set_permissions(struct ulogd_pluginstance *upi)
{
	const char *socket_path;
	const char *owner = owner_ce(upi->config_kset).u.string;
	const char *group = group_ce(upi->config_kset).u.string;
	uid_t uid = (uid_t)-1;
	gid_t gid = (gid_t)-1;

	socket_path = unixpath_ce(upi->config_kset).u.string;

	if (chmod(socket_path, perms_ce(upi->config_kset).u.value) < 0) {
		ulogd_log(ULOGD_ERROR, "Could not set permissions on unix socket\n");
		return -1;
	}

	if (owner && strlen(owner)>0) {
		struct passwd *p = getpwnam(owner);

		if (p == NULL) {
			ulogd_log(ULOGD_ERROR, "Invalid owner specified for unix socket (%s)\n", owner);
			return -1;
		}

		uid = p->pw_uid;
	}

	if (group && strlen(group)>0) {
		struct group *g = getgrnam(group);

		if (g == NULL) {
			ulogd_log(ULOGD_ERROR, "Invalid group specified for unix socket (%s)\n", group);
			return -1;
		}

		gid = g->gr_gid;
	}

	if (chown(socket_path, uid, gid) < 0) {
		ulogd_log(ULOGD_ERROR, "Could not set owner/group of unix socket\n");
		return -1;
	}

	return 0;
}

/* warning: this code is NOT reentrant ! */
static void _timer_unregister_cb(struct ulogd_timer *a, void *param)
{
	struct unixsock_input *ui = param;

	if (ui->unixsock_instance_fd.fd >= 0) {
		ulogd_log(ULOGD_DEBUG, "  removing client from list\n");
		ulogd_unregister_fd(&ui->unixsock_instance_fd);
		close(ui->unixsock_instance_fd.fd);
		ui->unixsock_instance_fd.fd = -1;
		ui->unixsock_buf_avail = 0;
	}
}

static void _disconnect_client(struct unixsock_input *ui)
{
	struct ulogd_timer *t = malloc(sizeof(struct ulogd_timer));

	/* we can't call ulogd_unregister_fd fd, it will segfault
	 * (unable to remove an entry while inside llist_for_each_entry)
	 * so we schedule removal for next loop
	 */
	ulogd_init_timer(t, ui, _timer_unregister_cb);
	ulogd_add_timer(t, 0);
}

/* callback called from ulogd core when fd is readable */
static int unixsock_instance_read_cb(int fd, unsigned int what, void *param)
{
	struct ulogd_pluginstance *upi = param;
	struct unixsock_input *ui = (struct unixsock_input*)upi->private;
	int len;
	u_int16_t needed_len;
	u_int32_t packet_sig;
	struct ulogd_unixsock_packet_t *unixsock_packet;

	char buf[4096];

	if (!(what & ULOGD_FD_READ))
		return 0;

	len = read(fd, buf, sizeof(buf));
	if (len < 0) {
		ulogd_log(ULOGD_NOTICE, "  read returned %d, errno is %d (%s)\n",
					len, errno, strerror(errno));
		exit(-1);
		return len;
	}
	if (len == 0) {
		_disconnect_client(ui);
		ulogd_log(ULOGD_DEBUG, "  client disconnected\n");
		return 0;
	}

	if (ui->unixsock_buf_avail + len > ui->unixsock_buf_size) {
		ulogd_log(ULOGD_NOTICE,
			  "We are losing events. Please consider using the clause "
			  "bufsize\n");
		return -1;
	}

	memcpy(ui->unixsock_buf + ui->unixsock_buf_avail, buf, len);
	ui->unixsock_buf_avail += len;

	while(1) {
		unixsock_packet = (void*)ui->unixsock_buf;
		packet_sig = ntohl(unixsock_packet->marker);
		if (packet_sig != ULOGD_SOCKET_MARK) {
			ulogd_log(ULOGD_ERROR,
				"ulogd2: invalid packet marked received "
				"(read %lx, expected %lx), closing socket.\n",
				packet_sig, ULOGD_SOCKET_MARK);
			_disconnect_client(ui);
			return -1;

		}

		needed_len = ntohs(unixsock_packet->total_size);

		if (ui->unixsock_buf_avail >= needed_len + sizeof(u_int32_t)) {
			ulogd_log(ULOGD_DEBUG,
			"  We have enough data (%d bytes required), handling packet\n",
					needed_len);

			if (handle_packet(upi, unixsock_packet, needed_len) != 0) {
				return -1;
			}
			/* consume data */
			ui->unixsock_buf_avail -= (sizeof(u_int32_t) + needed_len);
			if (ui->unixsock_buf_avail > 0) {
				/* we need to shift data .. */
				memmove(ui->unixsock_buf,
						ui->unixsock_buf + (sizeof(u_int32_t) + needed_len) ,
						ui->unixsock_buf_avail);
			} else {
				/* input buffer is empty, do not loop */
				return 0;
			}

		} else {
			ulogd_log(ULOGD_DEBUG, "  We have %d bytes, but need %d. Requesting more\n",
					ui->unixsock_buf_avail, needed_len + sizeof(u_int32_t));
			return 0;
		}

		/* handle_packet has shifted data in buffer */
	};

	return 0;
}

/* callback called from ulogd core when fd is readable */
static int unixsock_server_read_cb(int fd, unsigned int what, void *param)
{
	struct ulogd_pluginstance *upi = param;
	struct unixsock_input *ui = (struct unixsock_input*)upi->private;
	socklen_t len;
	int s;
	struct sockaddr_storage saddr;

	if (!(what & ULOGD_FD_READ))
		return 0;

	ulogd_log(ULOGD_DEBUG, "New server connected on unixsock socket\n");

	len = sizeof(saddr);
	s = accept(fd, (struct sockaddr*)&saddr, &len);
	if (s < 0) {
		ulogd_log(ULOGD_NOTICE,
				"  error while accepting new unixsock client, errno is %d (%s)\n",
				errno, strerror(errno));
		return len;
	}

	if (ui->unixsock_instance_fd.fd >= 0) {
		ulogd_log(ULOGD_NOTICE, "a client is already connecting, rejecting new connection");
		close(s);
		return 0;
	}

	ui->unixsock_instance_fd.fd = s;
	ui->unixsock_instance_fd.cb = &unixsock_instance_read_cb;
	ui->unixsock_instance_fd.data = upi;
	ui->unixsock_instance_fd.when = ULOGD_FD_READ;

	if (ulogd_register_fd(&ui->unixsock_instance_fd) < 0) {
		ulogd_log(ULOGD_ERROR, "unable to register client fd to ulogd\n");
		return -1;
	}

	return 0;
}

static int configure(struct ulogd_pluginstance *upi,
		     struct ulogd_pluginstance_stack *stack)
{
	ulogd_log(ULOGD_DEBUG, "parsing config file section `%s', "
		  "plugin `%s'\n", upi->id, upi->plugin->name);

	config_parse_file(upi->id, upi->config_kset);
	return 0;
}

static int start(struct ulogd_pluginstance *upi)
{
	struct unixsock_input *ui = (struct unixsock_input *) upi->private;
	int fd;

	ulogd_log(ULOGD_DEBUG, "Starting plugin `%s'\n",
		  upi->plugin->name);

	ui->path = unixpath_ce(upi->config_kset).u.string;

	ulogd_log(ULOGD_DEBUG, "Creating Unix socket `%s'\n",
		  ui->path);
	fd = _create_unix_socket(ui->path);
	if (fd < 0) {
		ulogd_log(ULOGD_ERROR, "Unable to create unix socket on `%s'\n",
			  ui->path);
		return -1;
	}

	if (_unix_socket_set_permissions(upi) < 0) {
		return -1;
	}

	ui->unixsock_buf_avail = 0;
	ui->unixsock_buf_size = bufsize_ce(upi->config_kset).u.value;

	if (ui->unixsock_buf_size == 0) {
		int fd_bufsize = 0;
		socklen_t optlen = sizeof(fd_bufsize);

		if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &fd_bufsize, &optlen) < 0) {
			ulogd_log(ULOGD_ERROR,
					"Could not determine socket buffer size. You have to use the clause "
					"bufsize\n");
			return -1;
		}
		ulogd_log(ULOGD_DEBUG, "bufsize is %d\n", fd_bufsize);

		ui->unixsock_buf_size = fd_bufsize;
	}
	ui->unixsock_buf = malloc(ui->unixsock_buf_size);

	ui->unixsock_server_fd.fd = fd;
	ui->unixsock_server_fd.cb = &unixsock_server_read_cb;
	ui->unixsock_server_fd.data = upi;
	ui->unixsock_server_fd.when = ULOGD_FD_READ;

	ui->unixsock_instance_fd.fd = -1;
	ui->unixsock_instance_fd.cb = &unixsock_instance_read_cb;
	ui->unixsock_instance_fd.data = upi;
	ui->unixsock_instance_fd.when = ULOGD_FD_READ;

	if (ulogd_register_fd(&ui->unixsock_server_fd) < 0) {
		ulogd_log(ULOGD_ERROR, "Unable to register fd to ulogd\n");
		return -1;
	}

	return 0;
}

static int stop(struct ulogd_pluginstance *upi)
{
	struct unixsock_input *ui = (struct unixsock_input *) upi->private;
	char *unix_path = unixpath_ce(upi->config_kset).u.string;

	ulogd_log(ULOGD_DEBUG, "Stopping plugin `%s'\n",
		  upi->plugin->name);

	if (unix_path)
		unlink(unix_path);

	free(ui->unixsock_buf);

	return 0;
}

struct ulogd_plugin libunixsock_plugin = {
	.name = "UNIXSOCK",
	.input = {
		.type = ULOGD_DTYPE_SOURCE,
	},
	.output = {
		.type = ULOGD_DTYPE_RAW,
		.keys = output_keys,
		.num_keys = ARRAY_SIZE(output_keys),
	},
	.priv_size 	= sizeof(struct unixsock_input),
	.configure 	= &configure,
	.start 		= &start,
	.stop 		= &stop,
	.config_kset 	= &libunixsock_kset,
	.version	= VERSION,
};

static void __attribute__ ((constructor)) init(void)
{
	ulogd_register_plugin(&libunixsock_plugin);
}
