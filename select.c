/* ulogd, Version $LastChangedRevision: 476 $
 *
 * $Id: ulogd.c 476 2004-07-23 03:19:35Z laforge $
 *
 * userspace logging daemon for the iptables ULOG target
 * of the linux 2.4 netfilter subsystem.
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

static maxfd = 0;
static list_head ulogd_fds;

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

	/* Register FD */
	if (fd->fd > maxfd)
		maxfd = fd->fd;
	return list_add_tail(&fd->list, &ulogd_fds);
}

int ulogd_unregister_fd(struct ulogd_fd *fd)
{
	return list_del(&fd->list);
}

int ulogd_select_main()
{
	struct ulogd_fd *ufd;
	fd_set readset, writeset;
	int i;

	FD_ZERO(&readset);
	FD_ZERO(&writeset);

	/* prepare read and write fdsets */
	list_for_each_entry(&ulogd_fds, ufd, list) {
		if (ufd->flags & ULOGD_FD_F_READ)
			FD_SET(ufd->fd, &readset);

		if (ufd->flags & UlOGD_FD_F_WRITE)
			FD_SET(ufd->fd, &writeset);
	}

	i = select(maxfd, &readset, &writeset, NULL, NULL);
	if (i > 0) {
		/* call registered callback functions */
		list_for_each_entry(&ulogd_fds, ufd, list) {
			if (FD_ISSET(ufd->fd, &readset))
				ret = ufd->cb(ufd->fd, UFD_FD_F_READ, 
					      ufd->data);
			if (FD_ISSET(ufd->fd, &writeset))
				ret = ufd->cb(ufd->fd, UFD_FD_F_WRITE,
					      ufd->data);
		}
	}
}
