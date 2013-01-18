/* timer implementation
 *
 * userspace logging daemon for the netfilter subsystem
 *
 * (C) 2006-2008 by Pablo Neira Ayuso <pablo@netfilter.org>
 *
 * based on previous works by:
 *
 * (C) 2000-2005 by Harald Welte <laforge@gnumonks.org>
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
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Description:
 *  This is the timer framework for ulogd, it works together with select()
 *  so that the daemon only wakes up when there are timers expired to run.
 *  This approach is more simple than the previous signal-based implementation
 *  that could wake up the daemon while running at any part of the code.
 *
 * TODO:
 *  - This piece of code has been extracted from conntrackd. Probably
 *    ulogd doesn't require such O(log n) scalable timer framework. Anyhow,
 *    we can simplify this code using the same API later, that would be
 *    quite straight forward.
 */

#include <ulogd/timer.h>
#include <stdlib.h>
#include <limits.h>

static struct rb_root alarm_root = RB_ROOT;

void ulogd_init_timer(struct ulogd_timer *t,
		      void *data,
		      void (*cb)(struct ulogd_timer *a, void *data))
{
	/* initialize the head to check whether a node is inserted */
	RB_CLEAR_NODE(&t->node);
	timerclear(&t->tv);
	t->data = data;
	t->cb = cb;
}

static void __add_timer(struct ulogd_timer *alarm)
{
	struct rb_node **new = &(alarm_root.rb_node);
	struct rb_node *parent = NULL;

	while (*new) {
		struct ulogd_timer *this;

		this = container_of(*new, struct ulogd_timer, node);

		parent = *new;
		if (timercmp(&alarm->tv, &this->tv, <))
			new = &((*new)->rb_left);
		else
			new = &((*new)->rb_right);
	}

	rb_link_node(&alarm->node, parent, new);
	rb_insert_color(&alarm->node, &alarm_root);
}

void ulogd_add_timer(struct ulogd_timer *alarm, unsigned long sc)
{
	struct timeval tv;

	ulogd_del_timer(alarm);
	alarm->tv.tv_sec = sc;
	alarm->tv.tv_usec = 0;
	gettimeofday(&tv, NULL);
	timeradd(&alarm->tv, &tv, &alarm->tv);
	__add_timer(alarm);
}

void ulogd_del_timer(struct ulogd_timer *alarm)
{
	/* don't remove a non-inserted node */
	if (!RB_EMPTY_NODE(&alarm->node)) {
		rb_erase(&alarm->node, &alarm_root);
		RB_CLEAR_NODE(&alarm->node);
	}
}

int ulogd_timer_pending(struct ulogd_timer *alarm)
{
	if (RB_EMPTY_NODE(&alarm->node))
		return 0;

	return 1;
}

static struct timeval *
calculate_next_run(struct timeval *cand,
		   struct timeval *tv,
		   struct timeval *next_run)
{
	if (cand->tv_sec != LONG_MAX) {
		if (timercmp(cand, tv, >))
			timersub(cand, tv, next_run);
		else {
			/* loop again inmediately */
			next_run->tv_sec = 0;
			next_run->tv_usec = 0;
		}
		return next_run;
	}
	return NULL;
}

struct timeval *ulogd_get_next_timer_run(struct timeval *next_run)
{
	struct rb_node *node;
	struct timeval tv;

	gettimeofday(&tv, NULL);

	node = rb_first(&alarm_root);
	if (node) {
		struct ulogd_timer *this;
		this = container_of(node, struct ulogd_timer, node);
		return calculate_next_run(&this->tv, &tv, next_run);
	}
	return NULL;
}

struct timeval *ulogd_do_timer_run(struct timeval *next_run)
{
	struct llist_head alarm_run_queue;
	struct rb_node *node;
	struct ulogd_timer *this;
	struct timeval tv;

	gettimeofday(&tv, NULL);

	INIT_LLIST_HEAD(&alarm_run_queue);
	for (node = rb_first(&alarm_root); node; node = rb_next(node)) {
		this = container_of(node, struct ulogd_timer, node);

		if (timercmp(&this->tv, &tv, >))
			break;

		llist_add(&this->list, &alarm_run_queue);
	}

	llist_for_each_entry(this, &alarm_run_queue, list) {
		rb_erase(&this->node, &alarm_root);
		RB_CLEAR_NODE(&this->node);
		this->cb(this, this->data);
	}

	return ulogd_get_next_timer_run(next_run);
}
