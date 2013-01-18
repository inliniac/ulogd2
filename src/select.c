/* select related functions
 *
 * (C) 2000-2005 by Harald Welte <laforge@gnumonks.org>
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

#include <fcntl.h>
#include <ulogd/ulogd.h>
#include <ulogd/linuxlist.h>

static int maxfd = 0;
static fd_set readset, writeset, exceptset;
static LLIST_HEAD(ulogd_fds);

int ulogd_register_fd(struct ulogd_fd *fd)
{
	int flags;

	/* make FD nonblocking */
	flags = fcntl(fd->fd, F_GETFL);
	if (flags < 0)
		return -1;
	flags |= O_NONBLOCK;
	flags = fcntl(fd->fd, F_SETFL, flags);
	if (flags < 0)
		return -1;

	if (fd->when & ULOGD_FD_READ)
		FD_SET(fd->fd, &readset);

	if (fd->when & ULOGD_FD_WRITE)
		FD_SET(fd->fd, &writeset);

	if (fd->when & ULOGD_FD_EXCEPT)
		FD_SET(fd->fd, &exceptset);

	/* Register FD */
	if (fd->fd > maxfd)
		maxfd = fd->fd;

	llist_add_tail(&fd->list, &ulogd_fds);

	return 0;
}

void ulogd_unregister_fd(struct ulogd_fd *fd)
{
	if (fd->when & ULOGD_FD_READ)
		FD_CLR(fd->fd, &readset);

	if (fd->when & ULOGD_FD_WRITE)
		FD_CLR(fd->fd, &writeset);

	if (fd->when & ULOGD_FD_EXCEPT)
		FD_CLR(fd->fd, &exceptset);

	llist_del(&fd->list);

	/* Improvement: recalculate maxfd iif fd->fd == maxfd */
	maxfd = -1;
	llist_for_each_entry(fd, &ulogd_fds, list) {
		if (fd->fd > maxfd)
			maxfd = fd->fd;
	}
}

int ulogd_select_main(struct timeval *tv)
{
	struct ulogd_fd *ufd;
	fd_set rds_tmp, wrs_tmp, exs_tmp;
	int i;

	rds_tmp = readset;
	wrs_tmp = writeset;
	exs_tmp = exceptset;

	i = select(maxfd+1, &rds_tmp, &wrs_tmp, &exs_tmp, tv);
	if (i > 0) {
		/* call registered callback functions */
		llist_for_each_entry(ufd, &ulogd_fds, list) {
			int flags = 0;

			if (FD_ISSET(ufd->fd, &rds_tmp))
				flags |= ULOGD_FD_READ;

			if (FD_ISSET(ufd->fd, &wrs_tmp))
				flags |= ULOGD_FD_WRITE;

			if (FD_ISSET(ufd->fd, &exs_tmp))
				flags |= ULOGD_FD_EXCEPT;

			if (flags)
				ufd->cb(ufd->fd, flags, ufd->data);
		}
	}
	return i;
}
