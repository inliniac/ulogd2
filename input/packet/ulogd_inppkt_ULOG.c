/* ulogd_inppkt_ULOG.c - stackable input plugin for ULOG packets -> ulogd2
 * (C) 2004 by Harald Welte <laforge@gnumonks.org>
 */

#include <ulogd/ulogd.h>
#include <ulogd/conffile.h>

#include <libipulog/libipulog.h>

/* Size of the socket recevive memory.  Should be at least the same size as the
 * 'nlbufsiz' module loadtime parameter of ipt_ULOG.o
 * If you have _big_ in-kernel queues, you may have to increase this number.  (
 * --qthreshold 100 * 1500 bytes/packet = 150kB  */
#define ULOGD_RMEM_DEFAULT	131071

/* Size of the receive buffer for the netlink socket.  Should be at least of
 * RMEM_DEFAULT size.  */
#define ULOGD_BUFSIZE_DEFAULT	150000


static config_entry_t bufsiz_ce = { NULL, "bufsize", CONFIG_TYPE_INT,       
				   CONFIG_OPT_NONE, 0,
				   { value: ULOGD_BUFSIZE_DEFAULT } }; 

static config_entry_t nlgroup_ce = { &bufsiz_ce, "nlgroup", CONFIG_TYPE_INT,
				     CONFIG_OPT_NONE, 0,
				     { value: ULOGD_NLGROUP_DEFAULT } };

static config_entry_t rmem_ce = { &nlgroup_ce, "rmem", CONFIG_TYPE_INT,
				  CONFIG_OPT_NONE, 0, 
				  { value: ULOGD_RMEM_DEFAULT } };

struct ulog_input {
	struct ipulog_handle *libulog_h;
	static unsigned char *libulog_buf;
	static struct ulogd_fd ulog_fd;
};

/* call all registered interpreters and hand the results over to 
 * propagate_results */
static void handle_packet(ulog_packet_msg_t *pkt)
{
	ulog_iret_t *ret;
        ulog_iret_t *allret = NULL;
	ulog_interpreter_t *ip;

	unsigned int i,j;

	/* If there are no interpreters registered yet,
	 * ignore this packet */
	if (!ulogd_interh_ids) {
		ulogd_log(ULOGD_NOTICE, 
			  "packet received, but no interpreters found\n");
		return;
	}

	for (i = 1; i <= ulogd_interh_ids; i++) {
		ip = ulogd_interh[i];
		/* call interpreter */
		if ((ret = ((ip)->interp)(ip, pkt))) {
			/* create references for result linked-list */
			for (j = 0; j < ip->key_num; j++) {
				if (IS_VALID(ip->result[j])) {
					ip->result[j].cur_next = allret;
					allret = &ip->result[j];
				}
			}
		}
	}
	propagate_results(allret);
	clean_results(ulogd_interpreters->result);
}

static struct ulog_read_cb(int fd, void *param)
{
	struct ulog_input *u = (struct ulog_input *)param;
	int len;

	while (len = ipulog_read(u->libulog_h, u->libulog_buf,
				 bufsiz_ce.u.value, 1)) {
		if (len <= 0) {
			/* this is not supposed to happen */
			ulogd_log(ULOGD_ERROR, "ipulog_read = %d! "
				  "ipulog_errno = %d, errno = %d\n",
				  len, ipulog_errno, errno);
			break;
		}
		while ((upkt = ipulog_get_paccket(u->libulog_h,
						  u->libulog_buf, len))) {
			DEBUGP("==> ulog packet received\n");
			handle_packet(upkt);
		}
	}
	return 0;
}

static struct ulog_input *new_instance()
{
	struct ulog_input *ui = malloc(sizeof(*ui));
	if (!ui)
		return NULL;

	ui->libulog_buf = malloc(bufsiz_ce.u.value);
	if (!ui->libulog_buf)
		return NULL;

	ui->libulog_h = ipulog_create_handle(
				ipulog_group2gmask(nlgroup_ce.u.value),
				rmem_ce.u.value);
	if (!libulog_h)
		return NULL;

	ui->ulog_fd.fd = ui->libulog_h->fd;
	ui->ulog_fd.cb = &ulog_read_cb;
	ui->ulog_fd.data = ui;

	return ui;
}

static struct ulogd_pluginstance *init()
{
	struct ulog_input *ui = new_instance();

	ulogd_register_fd(&ui->ulog_fd);
}

struct ulogd_plugin libulog_plugin = {
	.name = "ULOG",
	.input_type = ULOGD_DTYPE_NULL,
	.output_type = ULOGD_DTYPE_RAW,
	.constructor = &init,
	.input_fn = &input,
	.configs = &rmem_ce,
};

void _init(void)
{
	ulogd_register_plugin(&libulog_plugin);
}
