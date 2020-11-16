/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2017-2019  Intel Corporation. All rights reserved.
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

#include <ctype.h>
#include <stdio.h>
#include <errno.h>
#include <ell/ell.h>

#include "src/iwd.h"
#include "src/module.h"
#include "src/watchlist.h"
#include "src/simauth.h"

static struct l_queue *auth_providers;

struct iwd_sim_auth {
	const struct iwd_sim_auth_driver *driver;
	void *driver_data;
	bool aka_supported : 1;
	bool sim_supported : 1;
	char *nai;
	int pending;
	struct watchlist auth_watchers;
};

struct iwd_sim_auth *iwd_sim_auth_create(
		const struct iwd_sim_auth_driver *driver)
{
	struct iwd_sim_auth *auth = l_new(struct iwd_sim_auth, 1);

	auth->driver = driver;
	watchlist_init(&auth->auth_watchers, NULL);

	return auth;
}

void iwd_sim_auth_set_nai(struct iwd_sim_auth *auth, const char *nai)
{
	auth->nai = l_strdup(nai);
}

void iwd_sim_auth_set_capabilities(struct iwd_sim_auth *auth,
		bool sim_supported, bool aka_supported)
{
	auth->sim_supported = sim_supported;
	auth->aka_supported = aka_supported;
}

void iwd_sim_auth_set_data(struct iwd_sim_auth *auth, void *driver_data)
{
	auth->driver_data = driver_data;
}

bool iwd_sim_auth_register(struct iwd_sim_auth *auth)
{
	return l_queue_push_head(auth_providers, auth);
}

void *iwd_sim_auth_get_data(struct iwd_sim_auth *auth)
{
	return auth->driver_data;
}

static void destroy_provider(void *data)
{
	struct iwd_sim_auth *auth = data;

	if (auth->driver->remove)
		auth->driver->remove(auth);

	watchlist_destroy(&auth->auth_watchers);

	l_free(auth->nai);
	l_free(auth);
}

void iwd_sim_auth_remove(struct iwd_sim_auth *auth)
{
	if (auth->driver && auth->driver->cancel_request)
		auth->driver->cancel_request(auth, auth->pending);

	WATCHLIST_NOTIFY_NO_ARGS(&auth->auth_watchers,
			sim_auth_unregistered_cb_t);

	l_queue_remove(auth_providers, auth);

	destroy_provider(auth);
}

const char *iwd_sim_auth_get_nai(struct iwd_sim_auth *auth)
{
	return auth->nai;
}

struct iwd_sim_auth *iwd_sim_auth_find(bool sim, bool aka)
{
	struct iwd_sim_auth *auth;
	const struct l_queue_entry *entry;

	for (entry = l_queue_get_entries(auth_providers); entry;
			entry = entry->next) {
		auth = entry->data;

		if (sim && !auth->sim_supported)
			continue;

		if (aka && !auth->aka_supported)
			continue;

		return auth;
	}

	return NULL;
}

unsigned int sim_auth_unregistered_watch_add(struct iwd_sim_auth *auth,
		sim_auth_unregistered_cb_t cb, void *data)
{
	return watchlist_add(&auth->auth_watchers, cb, data, NULL);
}

void sim_auth_unregistered_watch_remove(struct iwd_sim_auth *auth,
		unsigned int id)
{
	watchlist_remove(&auth->auth_watchers, id);
}

int sim_auth_check_milenage(struct iwd_sim_auth *auth,
		const uint8_t *rand, const uint8_t *autn,
		sim_auth_check_milenage_cb_t cb, void *data)
{
	if (!auth->aka_supported)
		return -1;

	/* save ID in case simauth is destroyed */
	auth->pending = auth->driver->check_milenage(auth, rand, autn,
			cb, data);

	return auth->pending;
}

int sim_auth_run_gsm(struct iwd_sim_auth *auth, const uint8_t *rands,
		int num_rands, sim_auth_run_gsm_cb_t cb, void *data)
{
	if (!auth->sim_supported)
		return -1;

	/* save ID in case simauth is destroyed */
	auth->pending = auth->driver->run_gsm(auth, rands, num_rands, cb, data);

	return auth->pending;
}

void sim_auth_cancel_request(struct iwd_sim_auth *auth, int id)
{
	if (auth->driver->cancel_request)
		auth->driver->cancel_request(auth, id);
}

static int sim_auth_init(void)
{
	auth_providers = l_queue_new();
	return 0;
}

static void sim_auth_exit(void)
{
	if (l_queue_length(auth_providers) > 0)
		l_warn("Auth provider queue was not empty on exit!");

	l_queue_destroy(auth_providers, destroy_provider);
}

IWD_MODULE(simauth, sim_auth_init, sim_auth_exit)
