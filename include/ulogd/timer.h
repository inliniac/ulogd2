#ifndef _TIMER_H_
#define _TIMER_H_

#include <ulogd/linux_rbtree.h>
#include <ulogd/linuxlist.h>

#include <sys/time.h>

struct ulogd_timer {
	struct rb_node		node;
	struct llist_head	list;
	struct timeval		tv;
	void			*data;
	void			(*cb)(struct ulogd_timer *a, void *data);
};

void ulogd_init_timer(struct ulogd_timer *t,
		     void *data,
		     void (*cb)(struct ulogd_timer *a, void *data));
void ulogd_add_timer(struct ulogd_timer *alarm, unsigned long sc);
void ulogd_del_timer(struct ulogd_timer *alarm);
int ulogd_timer_pending(struct ulogd_timer *alarm);
struct timeval *ulogd_get_next_timer_run(struct timeval *next_timer);
struct timeval *ulogd_do_timer_run(struct timeval *next_timer);

#endif
