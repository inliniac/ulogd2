#ifndef ULOGD_SELECT_H
#define ULOGD_SELECT_H

#define ULOGD_FD_F_READ		0x0001
#define ULOGD_FD_F_WRITE	0x0002

struct ulogd_fd {
	struct list_head list;
	int fd;
	unsigned int flags;
	void *data;
	int (*cb)(int fd, int flags, void *data);
};


int ulogd_register_fd(struct ulogd_fd *fd);
int ulogd_unregister_fd(struct ulogd_fd *fd);
int ulogd_select_main();

#endif
