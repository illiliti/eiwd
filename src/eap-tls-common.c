/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2018-2019  Intel Corporation. All rights reserved.
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

#include <stdio.h>
#include <errno.h>
#include <ell/ell.h>

#include "ell/useful.h"
#include "src/missing.h"
#include "src/module.h"
#include "src/eap.h"
#include "src/eap-private.h"
#include "src/eap-tls-common.h"

struct databuf {
	uint8_t *data;
	size_t len;
	size_t capacity;
};

static struct databuf *databuf_new(size_t capacity)
{
	struct databuf *databuf;

	if (!capacity)
		return NULL;

	databuf = l_new(struct databuf, 1);
	databuf->data = l_malloc(capacity);
	databuf->capacity = capacity;

	return databuf;
}

static void databuf_append(struct databuf *databuf, const uint8_t *data,
								size_t data_len)
{
	size_t new_len;

	if (!databuf)
		return;

	new_len = databuf->len + data_len;

	if (new_len > databuf->capacity) {
		databuf->capacity = new_len * 2;
		databuf->data = l_realloc(databuf->data, databuf->capacity);
	}

	memcpy(databuf->data + databuf->len, data, data_len);

	databuf->len = new_len;
}

static void databuf_free(struct databuf *databuf)
{
	if (!databuf)
		return;

	l_free(databuf->data);
	l_free(databuf);
}

#define EAP_TLS_PDU_MAX_LEN 65536

#define EAP_TLS_HEADER_LEN  6

#define EAP_TLS_HEADER_OCTET_FLAGS 5
#define EAP_TLS_HEADER_OCTET_FRAG_LEN 6

enum eap_tls_flag {
	/* Reserved    = 0x00, */
	EAP_TLS_FLAG_S    = 0x20,
	EAP_TLS_FLAG_M    = 0x40,
	EAP_TLS_FLAG_L    = 0x80,
};

struct eap_tls_state {
	enum eap_tls_version version_negotiated;

	struct l_tls *tunnel;

	bool method_completed:1;
	bool phase2_failed:1;

	struct databuf *plain_buf;
	struct databuf *tx_pdu_buf;
	struct databuf *rx_pdu_buf;

	size_t tx_frag_offset;
	size_t tx_frag_last_len;

	bool expecting_frag_ack:1;
	bool tunnel_ready:1;
	bool tls_session_resumed:1;
	bool tls_cache_disabled:1;

	struct l_queue *ca_cert;
	struct l_certchain *client_cert;
	struct l_key *client_key;
	char **domain_mask;

	const struct eap_tls_variant_ops *variant_ops;
	void *variant_data;
};

static struct l_settings *eap_tls_session_cache;
static eap_tls_session_cache_load_func_t eap_tls_session_cache_load;
static eap_tls_session_cache_sync_func_t eap_tls_session_cache_sync;

static void __eap_tls_common_state_reset(struct eap_state *eap)
{
	struct eap_tls_state *eap_tls = eap_get_data(eap);
	const char *peer_id;

	eap_tls->version_negotiated = EAP_TLS_VERSION_NOT_NEGOTIATED;
	eap_tls->method_completed = false;
	eap_tls->phase2_failed = false;
	eap_tls->expecting_frag_ack = false;
	eap_tls->tunnel_ready = false;

	/*
	 * Keep the tunnel instance to avoid losing the authentication
	 * settings that we may have loaded with l_tls_set_auth_data()
	 * since .reset_state is not supposed to clear settings.
	 */
	if (eap_tls->tunnel)
		l_tls_reset(eap_tls->tunnel);

	/*
	 * Drop the TLS session cache for this peer if the overall EAP
	 * method didn't succeed.
	 *
	 * Additionally if the session was cached previously, meaning
	 * that we've had a successful authentication at least once before,
	 * and we now used session resumption successfully and the method
	 * failed, become suspicious of this server's TLS session
	 * resumption support.  Some authenticators strangely allow
	 * resumption but can't handle it all the way to EAP method
	 * success.  This improves the chances that authentication
	 * succeeds on the next attempt.
	 *
	 * Drop the cache even if we have no indication that the
	 * method failed but it just didn't succeed, to handle cases like
	 * the server getting stuck and a timout occuring at a higher
	 * layer.  The risk is that we may occasionally flush the session
	 * data when there was only a momentary radio issue, invalid
	 * phase2 credentials or decision to abort.  Those are not hot
	 * paths.
	 *
	 * Note: TLS errors before the ready callback are handled in l_tls.
	 */
	peer_id = eap_get_peer_id(eap);
	if (peer_id && eap_tls_session_cache && !eap_method_is_success(eap) &&
			l_settings_has_group(eap_tls_session_cache, peer_id)) {
		eap_tls_forget_peer(peer_id);

		if (eap_tls->tls_session_resumed)
			l_warn("EAP: method did not finish after successful TLS"
				" session resumption.  If this repeats consider"
				" disabling [Security].EAP-%sFastReauthentication",
				eap_get_method_name(eap));
	}

	eap_tls->tls_session_resumed = false;

	eap_tls->tx_frag_offset = 0;
	eap_tls->tx_frag_last_len = 0;

	if (eap_tls->plain_buf) {
		databuf_free(eap_tls->plain_buf);
		eap_tls->plain_buf = NULL;
	}

	if (eap_tls->tx_pdu_buf) {
		databuf_free(eap_tls->tx_pdu_buf);
		eap_tls->tx_pdu_buf = NULL;
	}

	if (eap_tls->rx_pdu_buf) {
		databuf_free(eap_tls->rx_pdu_buf);
		eap_tls->rx_pdu_buf = NULL;
	}
}

static void __eap_tls_common_state_free(struct eap_tls_state *eap_tls)
{
	if (eap_tls->ca_cert)
		l_queue_destroy(eap_tls->ca_cert,
					(l_queue_destroy_func_t)l_cert_free);
	if (eap_tls->client_cert)
		l_certchain_free(eap_tls->client_cert);

	if (eap_tls->client_key)
		l_key_free(eap_tls->client_key);

	l_strv_free(eap_tls->domain_mask);

	if (eap_tls->tunnel)
		l_tls_free(eap_tls->tunnel);

	l_free(eap_tls);
}

bool eap_tls_common_state_reset(struct eap_state *eap)
{
	struct eap_tls_state *eap_tls = eap_get_data(eap);

	__eap_tls_common_state_reset(eap);

	if (eap_tls->variant_ops->reset)
		eap_tls->variant_ops->reset(eap_tls->variant_data);

	return true;
}

void eap_tls_common_state_free(struct eap_state *eap)
{
	struct eap_tls_state *eap_tls = eap_get_data(eap);

	__eap_tls_common_state_reset(eap);

	eap_set_data(eap, NULL);

	if (eap_tls->variant_ops->destroy)
		eap_tls->variant_ops->destroy(eap_tls->variant_data);

	__eap_tls_common_state_free(eap_tls);
}

static void eap_tls_tunnel_debug(const char *str, void *user_data)
{
	struct eap_state *eap = user_data;

	l_info("%s: %s", eap_get_method_name(eap), str);
}

static void eap_tls_tunnel_data_send(const uint8_t *data, size_t data_len,
								void *user_data)
{
	struct eap_state *eap = user_data;
	struct eap_tls_state *eap_tls = eap_get_data(eap);

	if (!eap_tls->tx_pdu_buf)
		eap_tls->tx_pdu_buf = databuf_new(data_len);

	databuf_append(eap_tls->tx_pdu_buf, data, data_len);
}

static void eap_tls_tunnel_data_received(const uint8_t *data, size_t data_len,
								void *user_data)
{
	struct eap_state *eap = user_data;
	struct eap_tls_state *eap_tls = eap_get_data(eap);

	if (!eap_tls->plain_buf)
		eap_tls->plain_buf = databuf_new(data_len);

	databuf_append(eap_tls->plain_buf, data, data_len);
}

static void eap_tls_tunnel_ready(const char *peer_identity, void *user_data)
{
	struct eap_state *eap = user_data;
	struct eap_tls_state *eap_tls = eap_get_data(eap);

	eap_tls->tls_session_resumed =
		l_tls_get_session_resumed(eap_tls->tunnel);

	if (eap_tls->ca_cert && !peer_identity) {
		l_error("%s: TLS did not verify AP identity",
			eap_get_method_name(eap));
		eap_method_error(eap);
		return;
	}

	/*
	 * Since authenticator may not send us EAP-Success/EAP-Failure
	 * in cleartext for the outer EAP method, we reinforce
	 * the completion with a timer.
	 */
	eap_start_complete_timeout(eap);

	eap_tls->tunnel_ready = true;

	if (!eap_tls->variant_ops->tunnel_ready)
		return;

	if (!eap_tls->variant_ops->tunnel_ready(eap, peer_identity,
						eap_tls->tls_session_resumed))
		l_tls_close(eap_tls->tunnel);
}

static void eap_tls_debug_hint(void)
{
	if (!getenv("IWD_TLS_DEBUG"))
		l_debug("set the IWD_TLS_DEBUG environment variable to see "
			"more information");
}

static void eap_tls_tunnel_disconnected(enum l_tls_alert_desc reason,
						bool remote, void *user_data)
{
	struct eap_state *eap = user_data;
	struct eap_tls_state *eap_tls = eap_get_data(eap);

	l_info("%s: Tunnel has disconnected with alert: %s",
			eap_get_method_name(eap), l_tls_alert_to_str(reason));

	eap_tls->method_completed = true;
	eap_tls->tunnel_ready = false;
}

static bool eap_tls_validate_version(struct eap_state *eap,
							uint8_t flags_version)
{
	struct eap_tls_state *eap_tls = eap_get_data(eap);
	enum eap_tls_version version_proposed =
					flags_version & EAP_TLS_VERSION_MASK;

	if (eap_tls->version_negotiated == version_proposed)
		return true;

	if (!(flags_version & EAP_TLS_FLAG_S) ||
			eap_tls->version_negotiated !=
						EAP_TLS_VERSION_NOT_NEGOTIATED)
		return false;

	if (version_proposed < eap_tls->variant_ops->version_max_supported)
		eap_tls->version_negotiated = version_proposed;
	else
		eap_tls->version_negotiated =
				eap_tls->variant_ops->version_max_supported;

	return true;
}

static void eap_tls_send_fragment(struct eap_state *eap)
{
	struct eap_tls_state *eap_tls = eap_get_data(eap);
	size_t mtu = eap_get_mtu(eap);
	uint8_t buf[mtu];
	size_t len = eap_tls->tx_pdu_buf->len - eap_tls->tx_frag_offset;
	size_t header_len = EAP_TLS_HEADER_LEN;
	uint8_t position = 0;

	if (eap_get_method_type(eap) == EAP_TYPE_EXPANDED) {
		header_len += 7;
		position += 7;
	}

	buf[EAP_TLS_HEADER_OCTET_FLAGS + position] =
						eap_tls->version_negotiated;

	if (len > mtu - EAP_TLS_HEADER_LEN - position) {
		len = mtu - EAP_TLS_HEADER_LEN - position;
		buf[EAP_TLS_HEADER_OCTET_FLAGS + position] |= EAP_TLS_FLAG_M;
		eap_tls->expecting_frag_ack = true;
	}

	if (!eap_tls->tx_frag_offset) {
		buf[EAP_TLS_HEADER_OCTET_FLAGS + position] |= EAP_TLS_FLAG_L;
		l_put_be32(eap_tls->tx_pdu_buf->len,
				&buf[EAP_TLS_HEADER_OCTET_FRAG_LEN + position]);
		len -= 4;
		header_len += 4;
	}

	memcpy(buf + header_len,
		eap_tls->tx_pdu_buf->data + eap_tls->tx_frag_offset, len);
	eap_method_respond(eap, buf, header_len + len);

	eap_tls->tx_frag_last_len = len;
}

static bool needs_workaround(struct eap_state *eap)
{
	struct eap_tls_state *eap_tls = eap_get_data(eap);

	/*
	 * Windows Server 2008 - Network Policy Server (NPS) generates an
	 * invalid Compound MAC for Cryptobinding TLV when is used within PEAPv0
	 * due to incorrect parsing of the message containing TLS Client Hello.
	 * Setting L bit and including TLS Message Length field, even for the
	 * packets that do not require fragmentation, corrects the issue. The
	 * redundant TLS Message Length field in unfragmented packets doesn't
	 * seem to effect the other server implementations.
	 */
	return eap_get_method_type(eap) == EAP_TYPE_PEAP &&
			eap_tls->version_negotiated == EAP_TLS_VERSION_0 &&
			!eap_tls->tunnel_ready;
}

static void eap_tls_send_response(struct eap_state *eap,
					const uint8_t *pdu, size_t pdu_len)
{
	struct eap_tls_state *eap_tls = eap_get_data(eap);
	size_t msg_len = EAP_TLS_HEADER_LEN + pdu_len;
	bool set_tls_msg_len = needs_workaround(eap);

	msg_len += set_tls_msg_len ? 4 : 0;

	if (msg_len <= eap_get_mtu(eap)) {
		uint8_t *buf;
		uint8_t extra = 0;

		if (eap_get_method_type(eap) == EAP_TYPE_EXPANDED) {
			extra += 7;
			msg_len += 7;
		}

		buf = l_malloc(msg_len);

		buf[EAP_TLS_HEADER_OCTET_FLAGS + extra] =
						eap_tls->version_negotiated;

		if (set_tls_msg_len) {
			buf[extra + EAP_TLS_HEADER_OCTET_FLAGS] |=
								EAP_TLS_FLAG_L;
			l_put_be32(pdu_len,
				   &buf[extra + EAP_TLS_HEADER_OCTET_FRAG_LEN]);

			extra += 4;
		}

		memcpy(buf + EAP_TLS_HEADER_LEN + extra, pdu, pdu_len);

		eap_method_respond(eap, buf, msg_len);
		l_free(buf);
		return;
	}

	eap_tls->tx_frag_offset = 0;
	eap_tls_send_fragment(eap);
}

void eap_tls_common_send_empty_response(struct eap_state *eap)
{
	struct eap_tls_state *eap_tls = eap_get_data(eap);
	uint8_t buf[EAP_TLS_HEADER_LEN + 7];
	uint8_t position = 0;

	if (eap_get_method_type(eap) == EAP_TYPE_EXPANDED)
		position += 7;

	buf[EAP_TLS_HEADER_OCTET_FLAGS + position] = eap_tls->version_negotiated;

	eap_method_respond(eap, buf, EAP_TLS_HEADER_LEN + position);
}

static int eap_tls_init_request_assembly(struct eap_state *eap,
						const uint8_t *pkt, size_t len,
						uint8_t flags)
{
	struct eap_tls_state *eap_tls = eap_get_data(eap);
	size_t tls_msg_len;

	if (eap_tls->rx_pdu_buf) {
		/*
		 * EAP-TLS: RFC 5216 Section 3.1
		 *
		 * The L bit (length included) is set to indicate the presence
		 * of the four-octet TLS Message Length field, and MUST be set
		 * for the first fragment of a fragmented TLS message or set of
		 * messages.
		 */
		l_debug("%s: Server has set the L bit in the fragment other "
			"than the first of a fragmented TLS message.",
						eap_get_method_name(eap));

		return 0;
	}

	if (len < 4)
		return -EINVAL;

	tls_msg_len = l_get_be32(pkt);
	len -= 4;

	if (tls_msg_len > EAP_TLS_PDU_MAX_LEN) {
		l_warn("%s: Fragmented pkt size is larger than %u.",
				eap_get_method_name(eap), EAP_TLS_PDU_MAX_LEN);

		return -EINVAL;
	}

	if (tls_msg_len == len) {
		/*
		 * EAP-TLS: RFC 5216 Section 3.1
		 *
		 * The L bit (length included) is set to indicate the presence
		 * of the four-octet TLS Message Length field, and MUST be set
		 * for the first fragment of a fragmented TLS message or set of
		 * messages.
		 *
		 * EAP-TTLSv0: RFC 5281, Section 9.2.2:
		 * "Unfragmented messages MAY have the L bit set and include
		 * the length of the message (though this information is
		 * redundant)."
		 *
		 * Some of the PEAP server implementations set the L flag along
		 * with redundant TLS Message Length field for the un-fragmented
		 * packets.
		 */
		l_debug("%s: Server has set the redundant TLS Message Length "
					"field for the un-fragmented packet.",
						eap_get_method_name(eap));

		return -ENOMSG;
	}

	if (tls_msg_len < len) {
		l_warn("%s: Fragmented pkt size is smaller than the received "
					"packet.", eap_get_method_name(eap));

		return -EINVAL;
	}

	eap_tls->rx_pdu_buf = databuf_new(tls_msg_len);

	if (!(flags & EAP_TLS_FLAG_M)) {
		/*
		 * EAP-TLS: RFC 5216 Section 3.1
		 *
		 * The M bit (more fragments) is set on all but the last
		 * fragment.
		 *
		 * Note: Some of the EAP-TLS based server implementations break
		 * the protocol and do not set the M flag for the first packet
		 * during the fragmented transmission. To stay compatible with
		 * such devices, we have relaxed this requirement.
		 */
		l_debug("%s: Server has failed to set the M flag in the first"
				" packet of the fragmented transmission.",
						eap_get_method_name(eap));

		return -EAGAIN;
	}

	return 0;
}

static void eap_tls_send_fragmented_request_ack(struct eap_state *eap)
{
	eap_tls_common_send_empty_response(eap);
}

static bool eap_tls_handle_fragmented_response_ack(struct eap_state *eap,
								size_t len)
{
	struct eap_tls_state *eap_tls = eap_get_data(eap);

	if (len)
		return false;

	if (!eap_tls->tx_frag_last_len)
		return false;

	eap_tls->tx_frag_offset += eap_tls->tx_frag_last_len;
	eap_tls->tx_frag_last_len = 0;
	eap_tls->expecting_frag_ack = false;

	eap_tls_send_fragment(eap);

	return true;
}

static int eap_tls_handle_fragmented_request(struct eap_state *eap,
						const uint8_t *pkt,
						size_t len,
						uint8_t flags_version)
{
	struct eap_tls_state *eap_tls = eap_get_data(eap);
	int r = 0;

	if (flags_version & EAP_TLS_FLAG_L) {
		r = eap_tls_init_request_assembly(eap, pkt, len, flags_version);
		if (r && r != -EAGAIN)
			return r;

		pkt += 4;
		len -= 4;
	}

	if (!eap_tls->rx_pdu_buf)
		return -EINVAL;

	if (eap_tls->rx_pdu_buf->capacity < eap_tls->rx_pdu_buf->len + len) {
		l_error("%s: Request fragment pkt size mismatch.",
						eap_get_method_name(eap));
		return -EINVAL;
	}

	databuf_append(eap_tls->rx_pdu_buf, pkt, len);

	if (flags_version & EAP_TLS_FLAG_M)
		return -EAGAIN;

	return r;
}

static void eap_tls_session_cache_update(void *user_data)
{
	if (L_WARN_ON(!eap_tls_session_cache_sync) ||
			L_WARN_ON(!eap_tls_session_cache))
		return;

	eap_tls_session_cache_sync(eap_tls_session_cache);
}

static bool eap_tls_tunnel_init(struct eap_state *eap)
{
	struct eap_tls_state *eap_tls = eap_get_data(eap);

	if (eap_tls->tunnel)
		goto start;

	eap_tls->tunnel = l_tls_new(false, eap_tls_tunnel_data_received,
					eap_tls_tunnel_data_send,
					eap_tls_tunnel_ready,
					eap_tls_tunnel_disconnected,
					eap);

	if (!eap_tls->tunnel) {
		l_error("%s: Failed to create a TLS instance.",
						eap_get_method_name(eap));
		return false;
	}

	if (getenv("IWD_TLS_DEBUG")) {
		l_tls_set_debug(eap_tls->tunnel, eap_tls_tunnel_debug, eap,
									NULL);
		l_tls_set_cert_dump_path(eap_tls->tunnel,
					"/tmp/iwd-tls-debug-server-cert.pem");
	}

	if (eap_tls->client_cert || eap_tls->client_key) {
		if (!l_tls_set_auth_data(eap_tls->tunnel, eap_tls->client_cert,
						eap_tls->client_key)) {
			l_certchain_free(eap_tls->client_cert);
			eap_tls->client_cert = NULL;

			l_key_free(eap_tls->client_key);
			eap_tls->client_key = NULL;

			l_error("%s: Failed to set auth data.",
					eap_get_method_name(eap));
			eap_tls_debug_hint();
			return false;
		}

		eap_tls->client_cert = NULL;
		eap_tls->client_key = NULL;
	}

	if (eap_tls->ca_cert) {
		if (!l_tls_set_cacert(eap_tls->tunnel, eap_tls->ca_cert)) {
			l_queue_destroy(eap_tls->ca_cert,
					(l_queue_destroy_func_t)l_cert_free);
			eap_tls->ca_cert = NULL;
			l_error("%s: Error settings CA certificates.",
					eap_get_method_name(eap));
			eap_tls_debug_hint();
			return false;
		}

		eap_tls->ca_cert = NULL;
	}

	if (eap_tls->domain_mask)
		l_tls_set_domain_mask(eap_tls->tunnel, eap_tls->domain_mask);

	if (!eap_tls_session_cache_load || eap_tls->tls_cache_disabled)
		goto start;

	if (!eap_tls_session_cache)
		eap_tls_session_cache = eap_tls_session_cache_load();

	l_tls_set_session_cache(eap_tls->tunnel, eap_tls_session_cache,
				eap_get_peer_id(eap),
				24 * 3600 * L_USEC_PER_SEC, 0,
				eap_tls_session_cache_update, NULL);

start:
	if (!l_tls_start(eap_tls->tunnel)) {
		l_error("%s: Failed to start the TLS client",
						eap_get_method_name(eap));
		eap_tls_debug_hint();
		return false;
	}

	return true;
}

static void eap_tls_handle_phase2_payload(struct eap_state *eap,
							const uint8_t *pkt,
							size_t pkt_len)
{
	struct eap_tls_state *eap_tls = eap_get_data(eap);

	if (!eap_tls->variant_ops->tunnel_handle_request)
		return;

	if (!eap_tls->variant_ops->tunnel_handle_request(eap, pkt, pkt_len))
		/*
		 * The tunneled packet payload that violates the protocol or
		 * fails a method-specific integrity check result in tunnel
		 * shutdown.
		 */
		l_tls_close(eap_tls->tunnel);
}

void eap_tls_common_handle_request(struct eap_state *eap,
					const uint8_t *pkt, size_t len)
{
	struct eap_tls_state *eap_tls = eap_get_data(eap);
	uint8_t flags_version;

	if (eap_tls->method_completed)
		return;

	if (len < 1) {
		l_error("%s: Request packet is too short.",
						eap_get_method_name(eap));
		goto error;
	}

	flags_version = pkt[0];

	if (!eap_tls_validate_version(eap, flags_version)) {
		l_error("%s: Version negotiation has failed.",
						eap_get_method_name(eap));
		goto error;
	}

	pkt += 1;
	len -= 1;

	if (eap_tls->expecting_frag_ack) {
		if (!eap_tls_handle_fragmented_response_ack(eap, len))
			goto error;

		return;
	}

	if (flags_version & EAP_TLS_FLAG_L || eap_tls->rx_pdu_buf) {
		int r = eap_tls_handle_fragmented_request(eap, pkt, len,
								flags_version);

		if (r == -EAGAIN) {
			/* Expecting more fragments. */
			eap_tls_send_fragmented_request_ack(eap);

			return;
		}

		if (r == -ENOMSG) {
			/*
			 * Redundant usage of the L flag, no packet reassembly
			 * is required.
			 */
			pkt += 4;
			len -= 4;

			goto proceed;
		}

		if (r < 0)
			goto error;

		if (eap_tls->rx_pdu_buf->capacity != eap_tls->rx_pdu_buf->len) {
			l_error("%s: Request fragment packet size mismatch",
						eap_get_method_name(eap));
			goto error;
		}

		pkt = eap_tls->rx_pdu_buf->data;
		len = eap_tls->rx_pdu_buf->len;
	}

proceed:
	if (eap_tls->tx_pdu_buf) {
		/*
		 * tx_pdu_buf is used for the re-transmission and needs to be
		 * cleared on a new request.
		*/
		databuf_free(eap_tls->tx_pdu_buf);
		eap_tls->tx_pdu_buf = NULL;
	}

	if (flags_version & EAP_TLS_FLAG_S) {
		if (!eap_tls_tunnel_init(eap))
			goto error;
	}

	if (len)
		l_tls_handle_rx(eap_tls->tunnel, pkt, len);

	if (eap_tls->plain_buf) {
		/*
		 * An existence of the plain_buf indicates that the TLS tunnel
		 * has been established and Phase 2 payload was transmitted
		 * through it.
		 */
		eap_tls_handle_phase2_payload(eap, eap_tls->plain_buf->data,
						eap_tls->plain_buf->len);

		databuf_free(eap_tls->plain_buf);
		eap_tls->plain_buf = NULL;
	}

	if (eap_tls->rx_pdu_buf) {
		databuf_free(eap_tls->rx_pdu_buf);
		eap_tls->rx_pdu_buf = NULL;
	}

	if (!eap_tls->tx_pdu_buf) {
		if (eap_tls->phase2_failed)
			goto error;

		return;
	}

	eap_tls_send_response(eap, eap_tls->tx_pdu_buf->data,
						eap_tls->tx_pdu_buf->len);

	if (eap_tls->phase2_failed)
		goto error;

	return;

error:
	eap_method_error(eap);
}

void eap_tls_common_handle_retransmit(struct eap_state *eap,
						const uint8_t *pkt, size_t len)
{
	struct eap_tls_state *eap_tls = eap_get_data(eap);
	uint8_t flags_version;

	if (len < 1) {
		l_error("%s: Request packet is too short.",
						eap_get_method_name(eap));
		goto error;
	}

	flags_version = pkt[0];

	if (!eap_tls_validate_version(eap, flags_version)) {
		l_error("%s: Version negotiation has failed.",
						eap_get_method_name(eap));
		goto error;
	}

	if (flags_version & EAP_TLS_FLAG_M) {
		if (!eap_tls->rx_pdu_buf)
			goto error;

		eap_tls_send_fragmented_request_ack(eap);

		return;
	}

	if (!eap_tls->tx_pdu_buf || !eap_tls->tx_pdu_buf->data ||
						!eap_tls->tx_pdu_buf->len)
		goto error;

	if (EAP_TLS_HEADER_LEN + eap_tls->tx_pdu_buf->len > eap_get_mtu(eap))
		eap_tls_send_fragment(eap);
	else
		eap_tls_send_response(eap, eap_tls->tx_pdu_buf->data,
						eap_tls->tx_pdu_buf->len);

	return;

error:
	eap_method_error(eap);
}

static const char *load_embedded_pem(struct l_settings *settings,
					const char *name)
{
	const char *pem;
	const char *type;

	pem = l_settings_get_embedded_value(settings, name + 6, &type);
	if (!pem)
		return NULL;

	if (strcmp(type, "pem"))
		return NULL;

	return pem;
}

static bool is_embedded(const char *str)
{
	if (!str)
		return false;

	if (strlen(str) < 6)
		return false;

	if (!strncmp("embed:", str, 6))
		return true;

	return false;
}

static struct l_queue *eap_tls_load_ca_cert(struct l_settings *settings,
						const char *value)
{
	const char *pem;

	if (!is_embedded(value))
		return l_pem_load_certificate_list(value);

	pem = load_embedded_pem(settings, value);
	if (!pem)
		return NULL;

	return l_pem_load_certificate_list_from_data(pem, strlen(pem));
}

struct l_certchain *eap_tls_load_client_cert(struct l_settings *settings,
						const char *value,
						const char *passphrase,
						bool *out_is_encrypted)
{
	const char *pem;

	if (!is_embedded(value)) {
		struct l_certchain *certchain;

		if (l_cert_load_container_file(value, passphrase,
						&certchain, NULL,
						out_is_encrypted))
			return certchain;

		if (out_is_encrypted)
			*out_is_encrypted = false;

		return NULL;
	}

	pem = load_embedded_pem(settings, value);
	if (!pem)
		return NULL;

	return l_pem_load_certificate_chain_from_data(pem, strlen(pem));
}

struct l_key *eap_tls_load_priv_key(struct l_settings *settings,
					const char *value,
					const char *passphrase,
					bool *out_is_encrypted)
{
	const char *pem;

	if (!is_embedded(value)) {
		struct l_key *key;

		if (l_cert_load_container_file(value, passphrase, NULL, &key,
						out_is_encrypted))
			return key;

		if (out_is_encrypted)
			*out_is_encrypted = false;

		return NULL;
	}

	pem = load_embedded_pem(settings, value);
	if (!pem)
		return NULL;

	return l_pem_load_private_key_from_data(pem, strlen(pem),
						passphrase, out_is_encrypted);
}

int eap_tls_common_settings_check(struct l_settings *settings,
					struct l_queue *secrets,
					const char *prefix,
					struct l_queue **out_missing)
{
	char setting_key[72];
	bool have_cacerts = false;
	const char *domain_mask_str;
	L_AUTO_FREE_VAR(char *, value);

	snprintf(setting_key, sizeof(setting_key), "%sCACert", prefix);
	value = l_settings_get_string(settings, "Security", setting_key);
	if (value) {
		struct l_queue *cacerts = eap_tls_load_ca_cert(settings, value);

		if (!cacerts) {
			l_error("Failed to load %s", value);
			return -EIO;
		}

		l_queue_destroy(cacerts,
				(l_queue_destroy_func_t) l_cert_free);
		have_cacerts = true;
	}

	/*
	 * Require CACert if ServerDomainMask is present.  If the server
	 * certificate is not being checked against any trusted certificates
	 * there's no point validating its contents and we wouldn't even
	 * receive the subject DN from ell, because it may be freely made up.
	 */
	snprintf(setting_key, sizeof(setting_key), "%sServerDomainMask",
			prefix);
	domain_mask_str = l_settings_get_value(settings, "Security",
						setting_key);
	if (domain_mask_str && !have_cacerts) {
		l_error("%s was set but no CA Certificates given", setting_key);
		return -EINVAL;
	}

	snprintf(setting_key, sizeof(setting_key),
					"%sFastReauthentication", prefix);

	if (l_settings_has_key(settings, "Security", setting_key) &&
			!l_settings_get_bool(settings, "Security",
						setting_key, NULL)) {
		l_error("Can't parse %s", setting_key);
		return -EINVAL;
	}

	return 0;
}

bool eap_tls_common_settings_load(struct eap_state *eap,
				struct l_settings *settings, const char *prefix,
				const struct eap_tls_variant_ops *variant_ops,
				void *variant_data)
{
	struct eap_tls_state *eap_tls;
	char setting_key[72];
	char *domain_mask_str;
	bool bool_val;

	L_AUTO_FREE_VAR(char *, value) = NULL;

	eap_tls = l_new(struct eap_tls_state, 1);

	eap_tls->version_negotiated = EAP_TLS_VERSION_NOT_NEGOTIATED;
	eap_tls->variant_ops = variant_ops;
	eap_tls->variant_data = variant_data;

	snprintf(setting_key, sizeof(setting_key), "%sCACert", prefix);
	value = l_settings_get_string(settings, "Security", setting_key);
	if (value) {
		eap_tls->ca_cert = eap_tls_load_ca_cert(settings, value);
		if (!eap_tls->ca_cert) {
			l_error("Could not load CACert %s", value);
			goto load_error;
		}
	}

	snprintf(setting_key, sizeof(setting_key), "%sServerDomainMask",
								prefix);
	domain_mask_str = l_settings_get_string(settings, "Security",
								setting_key);

	if (domain_mask_str) {
		eap_tls->domain_mask = l_strsplit(domain_mask_str, ';');
		l_free(domain_mask_str);
	}

	snprintf(setting_key, sizeof(setting_key),
					"%sFastReauthentication", prefix);

	if (!l_settings_get_bool(settings, "Security", setting_key, &bool_val))
		bool_val = true;

	eap_tls->tls_cache_disabled = !bool_val;

	eap_set_data(eap, eap_tls);

	return true;

load_error:
	__eap_tls_common_state_free(eap_tls);

	return false;
}

void eap_tls_common_set_keys(struct eap_state *eap,
				struct l_certchain *client_cert,
				struct l_key *client_key)
{
	struct eap_tls_state *eap_tls = eap_get_data(eap);

	eap_tls->client_cert = client_cert;
	eap_tls->client_key = client_key;
}

void eap_tls_common_set_completed(struct eap_state *eap)
{
	struct eap_tls_state *eap_tls = eap_get_data(eap);

	eap_tls->method_completed = true;
}

void eap_tls_common_set_phase2_failed(struct eap_state *eap)
{
	struct eap_tls_state *eap_tls = eap_get_data(eap);

	eap_tls->phase2_failed = true;
}

enum eap_tls_version eap_tls_common_get_negotiated_version(
							struct eap_state *eap)
{
	struct eap_tls_state *eap_tls = eap_get_data(eap);

	return eap_tls->version_negotiated;
}

void *eap_tls_common_get_variant_data(struct eap_state *eap)
{
	struct eap_tls_state *eap_tls = eap_get_data(eap);

	return eap_tls->variant_data;
}

bool eap_tls_common_tunnel_prf_get_bytes(struct eap_state *eap,
						bool use_master_secret,
						const char *label, uint8_t *buf,
						size_t buf_len)
{
	struct eap_tls_state *eap_tls = eap_get_data(eap);

	return l_tls_prf_get_bytes(eap_tls->tunnel, use_master_secret,
							label, buf, buf_len);
}

void eap_tls_common_tunnel_send(struct eap_state *eap, const uint8_t *data,
							size_t data_len)
{
	struct eap_tls_state *eap_tls = eap_get_data(eap);

	l_tls_write(eap_tls->tunnel, data, data_len);
}

void eap_tls_common_tunnel_close(struct eap_state *eap)
{
	struct eap_tls_state *eap_tls = eap_get_data(eap);

	l_tls_close(eap_tls->tunnel);
}

void eap_tls_set_session_cache_ops(eap_tls_session_cache_load_func_t load,
					eap_tls_session_cache_sync_func_t sync)
{
	eap_tls_session_cache_load = load;
	eap_tls_session_cache_sync = sync;
}

void eap_tls_forget_peer(const char *peer_id)
{
	if (L_WARN_ON(!eap_tls_session_cache_sync))
		return;

	if (!eap_tls_session_cache)
		eap_tls_session_cache = eap_tls_session_cache_load();

	if (l_settings_remove_group(eap_tls_session_cache, peer_id))
		eap_tls_session_cache_sync(eap_tls_session_cache);
}

static int eap_tls_common_init(void)
{
	return 0;
}

static void eap_tls_common_exit(void)
{
	l_settings_free(eap_tls_session_cache);
	eap_tls_session_cache = NULL;
}

IWD_MODULE(eap_tls_common, eap_tls_common_init, eap_tls_common_exit);
