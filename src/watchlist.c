/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2016-2019  Intel Corporation. All rights reserved.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <ell/ell.h>

#include "src/watchlist.h"

static bool watchlist_item_match(const void *a, const void *b)
{
	const struct watchlist_item *item = a;
	uint32_t id = L_PTR_TO_UINT(b);

	return item->id == id;
}

static void watchlist_item_free(struct watchlist *watchlist,
						struct watchlist_item *item)
{
	if (item->destroy)
		item->destroy(item->notify_data);

	if (watchlist->ops && watchlist->ops->item_free)
		watchlist->ops->item_free(item);
	else
		l_free(item);
}

void watchlist_init(struct watchlist *watchlist,
					const struct watchlist_ops *ops)
{
	watchlist->next_id = 0;
	watchlist->items = l_queue_new();
	watchlist->ops = ops;
}

unsigned int watchlist_link(struct watchlist *watchlist,
					struct watchlist_item *item,
					void *notify, void *notify_data,
					watchlist_item_destroy_func_t destroy)
{
	item->id = ++watchlist->next_id;
	item->notify = notify;
	item->notify_data = notify_data;
	item->destroy = destroy;

	l_queue_push_tail(watchlist->items, item);

	return item->id;
}

unsigned int watchlist_add(struct watchlist *watchlist, void *notify,
					void *notify_data,
					watchlist_item_destroy_func_t destroy)
{
	struct watchlist_item *item;

	item = l_new(struct watchlist_item, 1);
	return watchlist_link(watchlist, item, notify, notify_data, destroy);
}

bool watchlist_remove(struct watchlist *watchlist, unsigned int id)
{
	struct watchlist_item *item;

	if (watchlist->in_notify) {
		item = l_queue_find(watchlist->items, watchlist_item_match,
							L_UINT_TO_PTR(id));
		if (!item)
			return false;

		item->id = 0;	/* Mark stale */
		watchlist->stale_items = true;

		return true;
	}

	item = l_queue_remove_if(watchlist->items, watchlist_item_match,
							L_UINT_TO_PTR(id));
	if (!item)
		return false;

	watchlist_item_free(watchlist, item);

	return true;
}

static void watchlist_clear(struct watchlist *watchlist)
{
	struct watchlist_item *item;

	while ((item = l_queue_pop_head(watchlist->items)))
		watchlist_item_free(watchlist, item);
}

void watchlist_destroy(struct watchlist *watchlist)
{
	if (watchlist->in_notify) {
		watchlist->pending_destroy = true;
		return;
	}

	watchlist_clear(watchlist);
	l_queue_destroy(watchlist->items, NULL);
	watchlist->items = NULL;
}

void __watchlist_prune_stale(struct watchlist *watchlist)
{
	struct watchlist_item *item;

	while ((item = l_queue_remove_if(watchlist->items, watchlist_item_match,
							L_UINT_TO_PTR(0))))
		watchlist_item_free(watchlist, item);

	watchlist->stale_items = false;
}
