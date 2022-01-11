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

#include <stdint.h>
#include <stdbool.h>

#define EAP_AKA_KI_LEN		16
#define EAP_AKA_OPC_LEN		16
#define EAP_AKA_AMF_LEN		2
#define EAP_AKA_SQN_LEN		6
#define EAP_SIM_KC_LEN		8
#define EAP_SIM_SRES_LEN	4

#define NUM_RANDS_MAX		3

struct iwd_sim_auth;

typedef void (*sim_auth_unregistered_cb_t)(void *data);

/*
 * Callback containing Milenage keys.
 *
 * @param res		RES value
 * @param ck		CK key
 * @param ik		IK key
 * @param auts		AUTS key, if sync failure this will be non NULL. With a
 *			normal success, this should be NULL.
 * @param data		User data
 *
 * Note: If there was an error (invalid AUTN or some other error), all the keys
 * (res/ck/ik/auts) will be NULL. A sync error will result in res, ck, and ik
 * being NULL but auts should point to a valid AUTS key.
 */
typedef void (*sim_auth_check_milenage_cb_t)(const uint8_t *res,
		const uint8_t *ck, const uint8_t *ik, const uint8_t *auts,
		void *data);

/*
 * Callback with GSM data
 *
 * @param sres		SRES value
 * @param kc		Kc value
 * @param user_data	User data
 *
 * Note: If GSM authentication was unsuccessful sres and kc will both be NULL
 */
typedef void (*sim_auth_run_gsm_cb_t)(const uint8_t *sres,
		const uint8_t *kc, void *user_data);

struct iwd_sim_auth_driver {
	const char *name;
	int (*check_milenage)(struct iwd_sim_auth *auth, const uint8_t *rand,
			const uint8_t *autn,
			sim_auth_check_milenage_cb_t cb, void *data);
	int (*run_gsm)(struct iwd_sim_auth *auth, const uint8_t *rands,
			int num_rands, sim_auth_run_gsm_cb_t cb,
			void *data);
	void (*cancel_request)(struct iwd_sim_auth *auth, int id);
	void (*remove)(struct iwd_sim_auth *auth);
};

/*
 * Create a new authentication provider. This new provider will be added to
 * the list of available providers. It is expected that the auth provider
 * should be immediately available for auth requests.
 */
struct iwd_sim_auth *iwd_sim_auth_create(
		const struct iwd_sim_auth_driver *driver);

void iwd_sim_auth_set_nai(struct iwd_sim_auth *auth, const char *nai);

void iwd_sim_auth_set_capabilities(struct iwd_sim_auth *auth,
		bool sim_supported, bool aka_supported);

void iwd_sim_auth_set_data(struct iwd_sim_auth *auth, void *driver_data);

bool iwd_sim_auth_register(struct iwd_sim_auth *auth);

void *iwd_sim_auth_get_data(struct iwd_sim_auth *auth);

void iwd_sim_auth_remove(struct iwd_sim_auth *auth);

const char *iwd_sim_auth_get_nai(struct iwd_sim_auth *auth);

unsigned int sim_auth_unregistered_watch_add(struct iwd_sim_auth *auth,
		sim_auth_unregistered_cb_t cb, void *data);

void sim_auth_unregistered_watch_remove(struct iwd_sim_auth *auth,
		unsigned int id);
/*
 * Find an appropriate driver for running SIM/AKA algorithms
 *
 * @param sim		True if the driver should support SIM authentication
 * @param aka		True if the driver should support AKA authentication
 *
 * @returns		Driver handle found, NULL if none available
 */
struct iwd_sim_auth *iwd_sim_auth_find(bool sim, bool aka);
/*
 * Check that 'rand' and 'autn' are valid from the server.
 *
 * @param auth		Auth handle found with iwd_sim_auth_find()
 * @param rand		List of RAND's from the server
 * @param autn		AUTN from server
 * @param cb		Callback with milenage values
 * @param data		User data
 *
 * @return		Transaction ID, used to cancel the request if needed
 *			< 0 in case of an error
 */
int sim_auth_check_milenage(struct iwd_sim_auth *auth,
		const uint8_t *rand, const uint8_t *autn,
		sim_auth_check_milenage_cb_t cb, void *data);

/*
 * Retrieve EAP-SIM Kc and SRES values
 *
 * @param Auth		Auth handle found with iwd_sim_auth_find()
 * @param rands		Buffer containing N 16 byte RANDs (n == 2 || n == 3)
 * @param num_rands	Number of 16 byte RANDs in 'rand'
 * @param cb		Callback with GSM key values
 * @param data		User data
 *
 * @return		Transaction ID, used to cancel the request if needed
 *			< 0 in case of an error
 */
int sim_auth_run_gsm(struct iwd_sim_auth *auth, const uint8_t *rands,
		int num_rands, sim_auth_run_gsm_cb_t cb, void *data);

void sim_auth_cancel_request(struct iwd_sim_auth *auth, int id);
