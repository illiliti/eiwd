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

#include <string.h>
#include <assert.h>
#include <ell/ell.h>

#include "src/util.h"
#include "src/ie.h"
#include "src/handshake.h"
#include "src/mpdu.h"
#include "src/sae.h"
#include "src/auth-proto.h"

struct test_handshake_state {
	struct handshake_state super;
};

struct test_data {
	/* flag for testing anti clogging */
	bool test_anti_clogging;
	/* true if a commit message was sent and verified */
	bool commit_success;
	/* true if a confirm message was sent and verified */
	bool confirm_success;
	/* true if a rejection packet was sent */
	bool tx_reject_occurred;
	/* true if the tx function was called */
	bool tx_auth_called;
	bool tx_assoc_called;
	/* copy of clogging token (if present) */
	uint8_t test_clogging_token[32];
	/* copy of last packet sent */
	uint8_t tx_packet[512];
	size_t tx_packet_len;
	/* status in complete callback */
	uint16_t status;

	struct handshake_state *handshake;
};

struct authenticate_frame {
	struct mmpdu_header hdr;
	struct mmpdu_authentication auth;
} __attribute__ ((packed));

struct associate_frame {
	struct mmpdu_header hdr;
	struct mmpdu_association_response assoc;
} __attribute__ ((packed));

static uint8_t spa[] = {2, 0, 0, 0, 0, 0};
static uint8_t aa[] = {2, 0, 0, 0, 0, 1};
static char *passphrase = "secret123";

static void test_handshake_state_free(struct handshake_state *hs)
{
	struct test_handshake_state *ths =
			l_container_of(hs, struct test_handshake_state, super);

	l_free(ths);
}

static struct handshake_state *test_handshake_state_new(uint32_t ifindex)
{
	struct test_handshake_state *ths;

	ths = l_new(struct test_handshake_state, 1);

	ths->super.ifindex = ifindex;
	ths->super.free = test_handshake_state_free;

	return &ths->super;
}

static void test_tx_auth_func(const uint8_t *frame, size_t len, void *user_data)
{
	struct test_data *td = user_data;
	uint16_t trans;

	td->tx_auth_called = true;

	memset(td->tx_packet, 0, sizeof(td->tx_packet));
	memcpy(td->tx_packet, frame, len);
	td->tx_packet_len = len;

	if (len <= 6 && l_get_le16(frame + 2) != 0) {
		td->tx_reject_occurred = true;
		return;
	}

	trans = l_get_le16(frame);	/* transaction */

	switch (trans) {
	case 1:
		assert(l_get_le16(frame + 2) == 0);	/* status */
		assert(l_get_le16(frame + 4) == 19);	/* group */

		if (len > 102) {
			/* clogging token */
			assert(len == 134);
			assert(!memcmp(frame + 6, td->test_clogging_token, 32));
		} else {
			assert(len == 102);
		}

		td->commit_success = true;

		return;
	case 2:
		assert(l_get_le16(frame + 2) == 0);
		assert(len == 38);

		td->confirm_success = true;

		return;
	}

	assert(false);
}

static void test_tx_assoc_func(void *user_data)
{
	struct test_data *td = user_data;

	td->tx_assoc_called = true;
}

static struct auth_proto *test_initialize(struct test_data *td)
{
	struct auth_proto *ap;
	struct handshake_state *hs = test_handshake_state_new(1);

	td->handshake = hs;

	handshake_state_set_supplicant_address(hs, spa);
	handshake_state_set_authenticator_address(hs, aa);
	handshake_state_set_passphrase(hs, passphrase);

	memset(td->test_clogging_token, 0xde, 32);

	ap = sae_sm_new(hs, test_tx_auth_func, test_tx_assoc_func, td);

	td->commit_success = false;
	auth_proto_start(ap);

	assert(td->commit_success == true);

	return ap;
}

static void test_destruct(struct test_data *td)
{
	handshake_state_free(td->handshake);
	l_free(td);
}

static uint8_t aa_commit[] = {
	0x13, 0x00, 0x50, 0x5b, 0xb2, 0x1f, 0xaf, 0x7d,
	0xaf, 0x14, 0x7c, 0x7b, 0x19, 0xc9, 0x72, 0x82, 0xbc, 0x1a, 0xdb, 0xa1,
	0xbd, 0x6e, 0x5a, 0xc7, 0x58, 0x0a, 0x65, 0x1f, 0xd2, 0xde, 0xb0, 0x66,
	0xa5, 0xf9, 0x3e, 0x95, 0x4a, 0xe1, 0x83, 0xdb, 0x8a, 0xf5, 0x47, 0x8a,
	0x9d, 0x88, 0x5b, 0x58, 0xb9, 0x5b, 0xfb, 0x99, 0xff, 0xbe, 0xa0, 0xe8,
	0x70, 0x9d, 0x99, 0x2e, 0x8f, 0xa3, 0x53, 0x57, 0x3c, 0x49, 0x81, 0x0e,
	0xbc, 0x8f, 0xbc, 0xe7, 0x77, 0x8a, 0x5b, 0xf0, 0xae, 0x4a, 0xfb, 0xcd,
	0x81, 0xc0, 0x97, 0xb2, 0xf8, 0xb9, 0x12, 0xed, 0x3b, 0xd5, 0x3c, 0x5c,
	0xb2, 0x3a, 0xcc, 0x22, 0xe3, 0x9e
};

static uint8_t aa_confirm[] = {
	0x00, 0x00, 0x03, 0x0e, 0xf7, 0x5c, 0x1c, 0xab,
	0x7c, 0x29, 0xa1, 0x79, 0x22, 0xe4, 0x3b, 0x64, 0xb8, 0xf0, 0x70, 0x25,
	0x40, 0xcc, 0x78, 0x81, 0x27, 0x12, 0xca, 0xa9, 0xf5, 0xe5, 0x0f, 0xa7,
	0x73, 0x6d
};

static size_t setup_auth_frame(struct authenticate_frame *frame,
				const uint8_t *addr,
				uint16_t trans, uint16_t status,
				const uint8_t *data, size_t len)
{
	memset(frame, 0, sizeof(struct authenticate_frame));
	memcpy(frame->hdr.address_2, addr, 6);

	frame->hdr.fc.type = MPDU_TYPE_MANAGEMENT;
	frame->hdr.fc.subtype = MPDU_MANAGEMENT_SUBTYPE_AUTHENTICATION;
	frame->hdr.fc.order = 1;

	l_put_le16(MMPDU_AUTH_ALGO_SAE, &frame->auth.algorithm);
	l_put_le16(trans, &frame->auth.transaction_sequence);
	l_put_le16(status, &frame->auth.status);

	if (data)
		memcpy(frame->auth.ies, data, len);

	return sizeof(frame->hdr) + sizeof(frame->auth) + len;
}

static size_t setup_assoc_frame(struct associate_frame *frame, uint16_t status)
{
	/*
	 * Only need the frame to verify with mpdu_validate and have status
	 * code set.
	 */
	memset(frame, 0, sizeof(struct associate_frame));

	frame->hdr.fc.type = MPDU_TYPE_MANAGEMENT;
	frame->hdr.fc.subtype = MPDU_MANAGEMENT_SUBTYPE_ASSOCIATION_REQUEST;
	frame->hdr.fc.order = 1;

	l_put_le16(status, &frame->assoc.status_code);

	return sizeof(frame->hdr) + sizeof(frame->assoc);
}

static void test_confirm_timeout(const void *arg)
{
	struct test_data *td = l_new(struct test_data, 1);
	struct auth_proto *ap = test_initialize(td);
	struct authenticate_frame *frame = alloca(
					sizeof(struct authenticate_frame) +
					sizeof(aa_commit));
	size_t len;
	int i;

	len = setup_auth_frame(frame, aa, 1, 0, aa_commit, sizeof(aa_commit));

	assert(auth_proto_rx_authenticate(ap, (uint8_t *)frame, len) == 0);

	assert(td->confirm_success);

	assert(l_get_le16(td->tx_packet + 4) == 1);

	for (i = 1; i < 5; i++) {
		assert(auth_proto_auth_timeout(ap));
		assert(l_get_le16(td->tx_packet + 4) == i + 1);
	}

	assert(!auth_proto_auth_timeout(ap));

	test_destruct(td);

	auth_proto_free(ap);
}

static void test_commit_timeout(const void *arg)
{
	struct test_data *td = l_new(struct test_data, 1);
	struct auth_proto *ap = test_initialize(td);
	uint8_t last_packet[512];
	int i;

	memcpy(last_packet, td->tx_packet, td->tx_packet_len);

	for (i = 0; i < 4; i++) {
		assert(auth_proto_auth_timeout(ap));

		assert(!memcmp(last_packet, td->tx_packet, td->tx_packet_len));

		memcpy(last_packet, td->tx_packet, td->tx_packet_len);
	}

	assert(!auth_proto_auth_timeout(ap));

	test_destruct(td);
	auth_proto_free(ap);
}

static void test_clogging(const void *arg)
{
	struct test_data *td = l_new(struct test_data, 1);
	struct auth_proto *ap = test_initialize(td);
	struct authenticate_frame *frame = alloca(
					sizeof(struct authenticate_frame) + 34);
	uint8_t extra[34];
	size_t len;

	l_put_le16(19, extra);
	memcpy(extra + 2, td->test_clogging_token, 32);

	len = setup_auth_frame(frame, aa, 1,
				MMPDU_STATUS_CODE_ANTI_CLOGGING_TOKEN_REQ,
				extra, sizeof(extra));

	td->test_anti_clogging = true;
	td->commit_success = false;

	assert(auth_proto_rx_authenticate(ap, (uint8_t *)frame, len) ==
						-EAGAIN);

	assert(td->commit_success == true);

	test_destruct(td);
	auth_proto_free(ap);
}

static void test_early_confirm(const void *arg)
{
	struct test_data *td = l_new(struct test_data, 1);
	struct auth_proto *ap = test_initialize(td);
	uint8_t first_commit[102];
	struct authenticate_frame *frame = alloca(
					sizeof(struct authenticate_frame) + 32);
	size_t len;

	/* save the initial commit */
	memcpy(first_commit, td->tx_packet, td->tx_packet_len);

	len = setup_auth_frame(frame, aa, 2, 0, NULL, 32);
	memset(frame->auth.ies, 0xfe, 32);

	td->test_anti_clogging = false;

	assert(auth_proto_rx_authenticate(ap, (uint8_t *)frame, len) ==
						-EAGAIN);

	/* verify earlier commit matched most recent */
	assert(!memcmp(td->tx_packet, first_commit, td->tx_packet_len));

	test_destruct(td);
	auth_proto_free(ap);
}

static void test_reflection(const void *arg)
{
	struct test_data *td = l_new(struct test_data, 1);
	struct auth_proto *ap = test_initialize(td);

	td->tx_auth_called = false;
	/* send reflect same commit */
	ap->rx_authenticate(ap, td->tx_packet, td->tx_packet_len);

	assert(td->tx_auth_called == false);

	test_destruct(td);
	auth_proto_free(ap);
}

static void test_malformed_commit(const void *arg)
{
	struct test_data *td = l_new(struct test_data, 1);
	struct auth_proto *ap = test_initialize(td);
	struct authenticate_frame *frame = alloca(
					sizeof(struct authenticate_frame) +
					sizeof(aa_commit));
	size_t len;

	len = setup_auth_frame(frame, aa, 1, 0, aa_commit, sizeof(aa_commit));

	/* don't send entire commit */
	assert(auth_proto_rx_authenticate(ap, (uint8_t *)frame, len - 20) != 0);

	test_destruct(td);
	auth_proto_free(ap);
}

static void test_malformed_confirm(const void *arg)
{
	struct test_data *td = l_new(struct test_data, 1);
	struct auth_proto *ap = test_initialize(td);
	struct authenticate_frame *frame = alloca(
					sizeof(struct authenticate_frame) +
					sizeof(aa_commit));
	size_t len;

	len = setup_auth_frame(frame, aa, 1, 0, aa_commit, sizeof(aa_commit));

	assert(auth_proto_rx_authenticate(ap, (uint8_t *)frame, len) == 0);

	assert(td->commit_success);

	frame = alloca(sizeof(struct authenticate_frame) + sizeof(aa_confirm));
	len = setup_auth_frame(frame, aa, 2, 0, aa_confirm, sizeof(aa_confirm));

	/* don't send entire confirm */
	assert(auth_proto_rx_authenticate(ap, (uint8_t *)frame, len - 10) != 0);

	test_destruct(td);
	auth_proto_free(ap);
}

static uint8_t aa_commit_bad_group[] = {
	0xff, 0x00, 0x50, 0x5b, 0xb2, 0x1f, 0xaf, 0x7d,
	0xaf, 0x14, 0x7c, 0x7b, 0x19, 0xc9, 0x72, 0x82, 0xbc, 0x1a, 0xdb, 0xa1,
	0xbd, 0x6e, 0x5a, 0xc7, 0x58, 0x0a, 0x65, 0x1f, 0xd2, 0xde, 0xb0, 0x66,
	0xa5, 0xf9, 0x3e, 0x95, 0x4a, 0xe1, 0x83, 0xdb, 0x8a, 0xf5, 0x47, 0x8a,
	0x9d, 0x88, 0x5b, 0x58, 0xb9, 0x5b, 0xfb, 0x99, 0xff, 0xbe, 0xa0, 0xe8,
	0x70, 0x9d, 0x99, 0x2e, 0x8f, 0xa3, 0x53, 0x57, 0x3c, 0x49, 0x81, 0x0e,
	0xbc, 0x8f, 0xbc, 0xe7, 0x77, 0x8a, 0x5b, 0xf0, 0xae, 0x4a, 0xfb, 0xcd,
	0x81, 0xc0, 0x97, 0xb2, 0xf8, 0xb9, 0x12, 0xed, 0x3b, 0xd5, 0x3c, 0x5c,
	0xb2, 0x3a, 0xcc, 0x22, 0xe3, 0x9e
};

static void test_bad_group(const void *arg)
{
	struct test_data *td = l_new(struct test_data, 1);
	struct auth_proto *ap = test_initialize(td);
	struct authenticate_frame *frame = alloca(
					sizeof(struct authenticate_frame) +
					sizeof(aa_commit_bad_group));
	size_t len;

	len = setup_auth_frame(frame, aa, 1, 0, aa_commit_bad_group,
				sizeof(aa_commit_bad_group));

	assert(auth_proto_rx_authenticate(ap, (uint8_t *)frame, len) ==
			MMPDU_STATUS_CODE_UNSUPP_FINITE_CYCLIC_GROUP);

	assert(td->tx_reject_occurred);

	test_destruct(td);
	auth_proto_free(ap);
}

static void end_to_end_tx_func(const uint8_t *frame, size_t len, void *user_data)
{
	struct test_data *td = user_data;

	memcpy(td->tx_packet, frame, len);
	td->tx_packet_len = len;
}

static void test_bad_confirm(const void *arg)
{
	struct auth_proto *ap1;
	struct auth_proto *ap2;
	struct test_data *td1 = l_new(struct test_data, 1);
	struct test_data *td2 = l_new(struct test_data, 1);
	struct handshake_state *hs1 = test_handshake_state_new(1);
	struct handshake_state *hs2 = test_handshake_state_new(2);
	struct authenticate_frame *frame = alloca(
				sizeof(struct authenticate_frame) + 512);
	size_t frame_len;
	uint8_t tmp_commit[512];
	size_t tmp_commit_len;

	td1->status = 0xffff;
	td2->status = 0xffff;

	handshake_state_set_supplicant_address(hs1, spa);
	handshake_state_set_authenticator_address(hs1, aa);
	handshake_state_set_passphrase(hs1, passphrase);

	handshake_state_set_supplicant_address(hs2, aa);
	handshake_state_set_authenticator_address(hs2, spa);
	handshake_state_set_passphrase(hs2, passphrase);
	handshake_state_set_authenticator(hs2, true);

	ap1 = sae_sm_new(hs1, end_to_end_tx_func, test_tx_assoc_func, td1);
	ap2 = sae_sm_new(hs2, end_to_end_tx_func, test_tx_assoc_func, td2);

	/* both peers send out commit */
	ap1->start(ap1);
	ap2->start(ap2);

	/* save sm1 commit, tx_packet will get overwritten with confirm */
	memcpy(tmp_commit, td1->tx_packet, td1->tx_packet_len);
	tmp_commit_len = td1->tx_packet_len;

	/* Setup whole frame */
	frame_len = setup_auth_frame(frame, aa, 1, 0, td2->tx_packet + 4,
					td2->tx_packet_len - 4);

	/* rx commit for both peers */
	ap1->rx_authenticate(ap1, (uint8_t *) frame, frame_len);

	frame_len = setup_auth_frame(frame, spa, 1, 0, tmp_commit + 4,
					tmp_commit_len - 4);
	ap2->rx_authenticate(ap2, (uint8_t *)frame, frame_len);
	/* both peers should now have sent confirm */

	/* rx confirm for both peers */
	frame_len = setup_auth_frame(frame, aa, 2, 0, td2->tx_packet + 4,
					td2->tx_packet_len - 4);
	ap1->rx_authenticate(ap1, (uint8_t *)frame, frame_len);

	/* muck with a byte in the confirm */
	td1->tx_packet[10] = ~td1->tx_packet[10];
	frame_len = setup_auth_frame(frame, spa, 2, 0, td1->tx_packet + 4,
					td1->tx_packet_len - 4);
	ap2->rx_authenticate(ap2, (uint8_t *)frame, frame_len);

	assert(td1->tx_assoc_called);
	assert(td2->status != 0);

	handshake_state_free(hs1);
	handshake_state_free(hs2);

	ap1->free(ap1);
	ap2->free(ap2);

	/* sm2 gets freed by sae since it failed */
	l_free(td1);
	l_free(td2);
}

static void test_confirm_after_accept(const void *arg)
{
	struct auth_proto *ap1;
	struct auth_proto *ap2;
	struct test_data *td1 = l_new(struct test_data, 1);
	struct test_data *td2 = l_new(struct test_data, 1);
	struct handshake_state *hs1 = test_handshake_state_new(1);
	struct handshake_state *hs2 = test_handshake_state_new(2);
	struct authenticate_frame *frame = alloca(
				sizeof(struct authenticate_frame) + 512);
	struct associate_frame *assoc = alloca(sizeof(struct associate_frame));
	size_t frame_len;
	uint8_t tmp_commit[512];
	size_t tmp_commit_len;

	td1->status = 0xffff;
	td2->status = 0xffff;

	handshake_state_set_supplicant_address(hs1, spa);
	handshake_state_set_authenticator_address(hs1, aa);
	handshake_state_set_passphrase(hs1, passphrase);

	handshake_state_set_supplicant_address(hs2, aa);
	handshake_state_set_authenticator_address(hs2, spa);
	handshake_state_set_passphrase(hs2, passphrase);
	handshake_state_set_authenticator(hs2, true);

	ap1 = sae_sm_new(hs1, end_to_end_tx_func, test_tx_assoc_func, td1);
	ap2 = sae_sm_new(hs2, end_to_end_tx_func, test_tx_assoc_func, td2);

	/* both peers send out commit */
	auth_proto_start(ap1);
	auth_proto_start(ap2);

	/* save sm1 commit, tx_packet will get overwritten with confirm */
	memcpy(tmp_commit, td1->tx_packet, td1->tx_packet_len);
	tmp_commit_len = td1->tx_packet_len;

	/* rx commit for both peers */
	frame_len = setup_auth_frame(frame, aa, 1, 0, td2->tx_packet + 4,
					td2->tx_packet_len - 4);
	assert(auth_proto_rx_authenticate(ap1, (uint8_t *)frame,
						frame_len) == 0);

	frame_len = setup_auth_frame(frame, spa, 1, 0, tmp_commit + 4,
					tmp_commit_len - 4);
	assert(auth_proto_rx_authenticate(ap2, (uint8_t *)frame,
						frame_len) == 0);
	/* both peers should now have sent confirm */

	/* rx confirm for one peer, sm1 should accept confirm */
	frame_len = setup_auth_frame(frame, aa, 2, 0, td2->tx_packet + 4,
					td2->tx_packet_len - 4);
	assert(auth_proto_rx_authenticate(ap1, (uint8_t *)frame,
						frame_len) == 0);

	assert(td1->tx_assoc_called);

	/* simulate sm2 not receiving confirm and resending its confirm */
	ap2->auth_timeout(ap2);
	frame_len = setup_auth_frame(frame, aa, 2, 0, td2->tx_packet + 4,
					td2->tx_packet_len - 4);
	assert(auth_proto_rx_authenticate(ap1, (uint8_t *)frame,
						frame_len) == 0);

	/* sc should be set to 0xffff */
	assert(l_get_u16(td1->tx_packet + 4) == 0xffff);
	/* sm1 should respond with a new confirm, and accept */
	frame_len = setup_auth_frame(frame, spa, 2, 0, td1->tx_packet + 4,
					td1->tx_packet_len - 4);
	assert(auth_proto_rx_authenticate(ap2, (uint8_t *)frame,
						frame_len) == 0);

	assert(td1->tx_assoc_called);

	frame_len = setup_assoc_frame(assoc, 0);

	/*
	 * This is just to complete the connection, SAE just verifies status
	 * so the same frame can be used for both SMs
	 */
	assert(auth_proto_rx_associate(ap1, (uint8_t *)assoc, frame_len) == 0);
	assert(auth_proto_rx_associate(ap2, (uint8_t *)assoc, frame_len) == 0);

	handshake_state_free(hs1);
	handshake_state_free(hs2);

	auth_proto_free(ap1);
	auth_proto_free(ap2);

	l_free(td1);
	l_free(td2);
}

static void test_end_to_end(const void *arg)
{
	struct auth_proto *ap1;
	struct auth_proto *ap2;
	struct test_data *td1 = l_new(struct test_data, 1);
	struct test_data *td2 = l_new(struct test_data, 1);
	struct handshake_state *hs1 = test_handshake_state_new(1);
	struct handshake_state *hs2 = test_handshake_state_new(2);
	struct authenticate_frame *frame = alloca(
				sizeof(struct authenticate_frame) + 512);
	struct associate_frame *assoc = alloca(sizeof(struct associate_frame));
	size_t frame_len;
	uint8_t tmp_commit[512];
	size_t tmp_commit_len;

	td1->status = 0xffff;
	td2->status = 0xffff;

	handshake_state_set_supplicant_address(hs1, spa);
	handshake_state_set_authenticator_address(hs1, aa);
	handshake_state_set_passphrase(hs1, passphrase);

	handshake_state_set_supplicant_address(hs2, aa);
	handshake_state_set_authenticator_address(hs2, spa);
	handshake_state_set_passphrase(hs2, passphrase);
	handshake_state_set_authenticator(hs2, true);

	ap1 = sae_sm_new(hs1, end_to_end_tx_func, test_tx_assoc_func, td1);
	ap2 = sae_sm_new(hs2, end_to_end_tx_func, test_tx_assoc_func, td2);

	/* both peers send out commit */
	auth_proto_start(ap1);
	auth_proto_start(ap2);

	/* save sm1 commit, tx_packet will get overwritten with confirm */
	memcpy(tmp_commit, td1->tx_packet, td1->tx_packet_len);
	tmp_commit_len = td1->tx_packet_len;

	/* rx commit for both peers */
	frame_len = setup_auth_frame(frame, aa, 1, 0, td2->tx_packet + 4,
					td2->tx_packet_len - 4);
	assert(auth_proto_rx_authenticate(ap1, (uint8_t *)frame,
						frame_len) == 0);

	/* both peers should now have sent confirm */
	frame_len = setup_auth_frame(frame, spa, 1, 0, tmp_commit + 4,
					tmp_commit_len - 4);
	assert(auth_proto_rx_authenticate(ap2, (uint8_t *)frame,
						frame_len) == 0);

	/* rx confirm for both peers */
	frame_len = setup_auth_frame(frame, aa, 2, 0, td2->tx_packet + 4,
					td2->tx_packet_len - 4);
	assert(auth_proto_rx_authenticate(ap1, (uint8_t *)frame,
						frame_len) == 0);

	frame_len = setup_auth_frame(frame, spa, 2, 0, td1->tx_packet + 4,
					td1->tx_packet_len - 4);
	assert(auth_proto_rx_authenticate(ap2, (uint8_t *)frame,
						frame_len) == 0);

	assert(td1->tx_assoc_called);
	assert(td2->tx_assoc_called);

	frame_len = setup_assoc_frame(assoc, 0);
	assert(auth_proto_rx_associate(ap1, (uint8_t *)assoc, frame_len) == 0);
	assert(auth_proto_rx_associate(ap2, (uint8_t *)assoc, frame_len) == 0);

	handshake_state_free(hs1);
	handshake_state_free(hs2);

	auth_proto_free(ap1);
	auth_proto_free(ap2);

	l_free(td1);
	l_free(td2);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	if (!l_getrandom_is_supported()) {
		l_info("l_getrandom not supported, skipping...");
		goto done;
	}

	if (!l_checksum_is_supported(L_CHECKSUM_SHA256, true)) {
		l_info("SHA256/HMAC_SHA256 not supported, skipping...");
		goto done;
	}

	l_test_add("SAE commit timeout", test_commit_timeout, NULL);
	l_test_add("SAE confirm timeout", test_confirm_timeout, NULL);
	l_test_add("SAE anti-clogging", test_clogging, NULL);
	l_test_add("SAE early confirm", test_early_confirm, NULL);
	l_test_add("SAE reflection", test_reflection, NULL);
	l_test_add("SAE malformed commit", test_malformed_commit, NULL);
	l_test_add("SAE malformed confirm", test_malformed_confirm, NULL);
	l_test_add("SAE bad group", test_bad_group, NULL);
	l_test_add("SAE bad confirm", test_bad_confirm, NULL);
	l_test_add("SAE confirm after accept", test_confirm_after_accept, NULL);
	l_test_add("SAE end-to-end", test_end_to_end, NULL);

done:
	return l_test_run();
}
