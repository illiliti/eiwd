
AM_MAKEFLAGS = --no-print-directory

ACLOCAL_AMFLAGS = -I build-aux

builtin_modules =
builtin_sources =

if EXTERNAL_ELL
ell_cflags = @ELL_CFLAGS@
ell_ldadd = @ELL_LIBS@
ell_dependencies =
ell_built_sources = ell/shared
else
ell_cflags =
ell_ldadd = ell/libell-internal.la
ell_dependencies = $(ell_ldadd)
ell_built_sources = ell/shared ell/internal ell/ell.h

noinst_LTLIBRARIES = ell/libell-internal.la

ell_headers = ell/util.h \
			ell/test.h \
			ell/strv.h \
			ell/utf8.h \
			ell/queue.h \
			ell/hashmap.h \
			ell/string.h \
			ell/settings.h \
			ell/main.h \
			ell/idle.h \
			ell/signal.h \
			ell/timeout.h \
			ell/io.h \
			ell/ringbuf.h \
			ell/log.h \
			ell/checksum.h \
			ell/netlink.h \
			ell/genl.h \
			ell/dbus.h \
			ell/rtnl.h \
			ell/dbus-service.h \
			ell/dbus-client.h \
			ell/hwdb.h \
			ell/cipher.h \
			ell/random.h \
			ell/uintset.h \
			ell/base64.h \
			ell/pem.h \
			ell/tls.h \
			ell/uuid.h \
			ell/key.h \
			ell/file.h \
			ell/dir.h \
			ell/net.h \
			ell/dhcp.h \
			ell/cert.h \
			ell/ecc.h \
			ell/ecdh.h \
			ell/time.h \
			ell/path.h \
			ell/icmp6.h \
			ell/dhcp6.h \
			ell/acd.h \
			ell/cleanup.h \
			ell/netconfig.h \
			ell/sysctl.h \
			ell/notifylist.h

ell_sources = ell/private.h \
			ell/missing.h \
			ell/util.c \
			ell/test.c \
			ell/strv.c \
			ell/utf8.c \
			ell/queue.c \
			ell/hashmap.c \
			ell/string.c \
			ell/settings.c \
			ell/main-private.h \
			ell/main.c \
			ell/idle.c \
			ell/signal.c \
			ell/timeout.c \
			ell/io.c \
			ell/ringbuf.c \
			ell/log.c \
			ell/checksum.c \
			ell/netlink-private.h \
			ell/netlink.c \
			ell/genl.c \
			ell/rtnl-private.h \
			ell/rtnl.c \
			ell/dbus-private.h \
			ell/dbus.c \
			ell/dbus-message.c \
			ell/dbus-util.c \
			ell/dbus-service.c \
			ell/dbus-client.c \
			ell/dbus-name-cache.c \
			ell/dbus-filter.c \
			ell/gvariant-private.h \
			ell/gvariant-util.c \
			ell/siphash-private.h \
			ell/siphash.c \
			ell/hwdb.c \
			ell/cipher.c \
			ell/random.c \
			ell/uintset.c \
			ell/base64.c \
			ell/asn1-private.h \
			ell/pem.c \
			ell/pem-private.h \
			ell/tls-private.h \
			ell/tls.c \
			ell/tls-record.c \
			ell/tls-suites.c \
			ell/tls-extensions.c \
			ell/uuid.c \
			ell/key.c \
			ell/file.c \
			ell/dir.c \
			ell/net-private.h \
			ell/net.c \
			ell/dhcp-private.h \
			ell/dhcp.c \
			ell/dhcp-transport.c \
			ell/dhcp-lease.c \
			ell/dhcp-util.c \
			ell/dhcp-server.c \
			ell/cert-private.h \
			ell/cert.c \
			ell/cert-crypto.c \
			ell/ecc-external.c \
			ell/ecc-private.h \
			ell/ecc.c \
			ell/ecdh.c \
			ell/time.c \
			ell/time-private.h \
			ell/path.c \
			ell/dhcp6.c \
			ell/dhcp6-private.h \
			ell/icmp6.c \
			ell/icmp6-private.h \
			ell/dhcp6-lease.c \
			ell/dhcp6-transport.c \
			ell/acd.c \
			ell/netconfig.c \
			ell/sysctl.c \
			ell/notifylist.c

ell_shared = ell/useful.h ell/asn1-private.h

ell_libell_internal_la_SOURCES = $(ell_headers) $(ell_sources) $(ell_shared)
endif

if LIBEDIT
client_cflags = $(LIBEDIT_CFLAGS)
client_ldadd = $(LIBEDIT_LIBS)
else
client_cflags =
client_ldadd = $(READLINE_LIBS)
endif

bin_PROGRAMS =
libexec_PROGRAMS =
noinst_PROGRAMS =

if DBUS_POLICY
dbus_datadir = @DBUS_DATADIR@/dbus-1/system.d
dist_dbus_data_DATA =
endif

if SYSTEMD_SERVICE
systemd_unitdir = @SYSTEMD_UNITDIR@
systemd_unit_DATA =

dbus_busdir = @DBUS_BUSDIR@
dbus_bus_DATA =

systemd_networkdir = @SYSTEMD_NETWORKDIR@
systemd_network_DATA =

systemd_modloaddir = @SYSTEMD_MODLOADDIR@
systemd_modload_DATA = src/pkcs8.conf
endif

if MANUAL_PAGES
man_MANS =
endif

manual_pages = src/iwd.8 src/iwd.debug.7 src/iwd.config.5 src/iwd.network.5 \
		src/iwd.ap.5 client/iwctl.1 monitor/iwmon.1 wired/ead.8 \
		tools/hwsim.1

eap_sources = src/eap.c src/eap.h src/eap-private.h \
				src/eap-md5.c \
				src/eap-tls.c \
				src/eap-ttls.c \
				src/eap-mschapv2.c src/eap-mschapv2.h \
				src/eap-sim.c \
				src/eap-aka.c \
				src/eap-peap.c \
				src/eap-gtc.c \
				src/eap-pwd.c \
				src/util.h src/util.c \
				src/crypto.h src/crypto.c \
				src/simutil.h src/simutil.c \
				src/simauth.h src/simauth.c \
				src/watchlist.h src/watchlist.c \
				src/eap-tls-common.h src/eap-tls-common.c \
				src/mschaputil.h src/mschaputil.c

if DAEMON
libexec_PROGRAMS += src/iwd

src_iwd_SOURCES = src/main.c linux/nl80211.h src/iwd.h src/missing.h \
					src/netdev.h src/netdev.c \
					src/wiphy.h src/wiphy.c \
					src/device.c \
					src/station.h src/station.c \
					src/ie.h src/ie.c \
					src/dbus.h src/dbus.c \
					src/mpdu.h src/mpdu.c \
					src/eapol.h src/eapol.c \
					src/eapolutil.h src/eapolutil.c \
					src/handshake.h src/handshake.c \
					src/scan.h src/scan.c \
					src/common.h src/common.c \
					src/agent.h src/agent.c \
					src/storage.h src/storage.c \
					src/network.h src/network.c \
					src/wsc.h src/wsc.c \
					src/backtrace.h src/backtrace.c \
					src/knownnetworks.h \
					src/knownnetworks.c \
					src/rfkill.h src/rfkill.c \
					src/ft.h src/ft.c \
					src/ap.h src/ap.c src/adhoc.c \
					src/sae.h src/sae.c \
					src/nl80211util.h src/nl80211util.c \
					src/nl80211cmd.h src/nl80211cmd.c \
					src/owe.h src/owe.c \
					src/blacklist.h src/blacklist.c \
					src/manager.c \
					src/erp.h src/erp.c \
					src/fils.h src/fils.c \
					src/auth-proto.h \
					src/anqp.h src/anqp.c \
					src/anqputil.h src/anqputil.c \
					src/netconfig.h src/netconfig.c\
					src/netconfig-commit.c \
					src/resolve.h src/resolve.c \
					src/hotspot.c \
					src/p2p.h src/p2p.c \
					src/p2putil.h src/p2putil.c \
					src/module.h src/module.c \
					src/rrm.c \
					src/frame-xchg.h src/frame-xchg.c \
					src/eap-wsc.c src/eap-wsc.h \
					src/wscutil.h src/wscutil.c \
					src/diagnostic.h src/diagnostic.c \
					src/ip-pool.h src/ip-pool.c \
					src/band.h src/band.c \
					src/sysfs.h src/sysfs.c \
					src/offchannel.h src/offchannel.c \
					src/dpp-util.h src/dpp-util.c \
					src/json.h src/json.c \
					src/dpp.c \
					src/udev.c \
					$(eap_sources) \
					$(builtin_sources)

src_iwd_LDADD = $(ell_ldadd) -ldl
src_iwd_DEPENDENCIES = $(ell_dependencies)

if OFONO
builtin_modules += ofono
builtin_sources += src/ofono.c
endif

if DBUS_POLICY
dist_dbus_data_DATA += src/iwd-dbus.conf
endif

if SYSTEMD_SERVICE
src_iwd_DEPENDENCIES += src/iwd.service

systemd_unit_DATA += src/iwd.service
dbus_bus_DATA += src/net.connman.iwd.service

systemd_network_DATA += src/80-iwd.link
endif

if MANUAL_PAGES
man_MANS += src/iwd.8 src/iwd.debug.7 src/iwd.config.5 src/iwd.network.5 \
		src/iwd.ap.5
endif
endif

if CLIENT
bin_PROGRAMS += client/iwctl

client_iwctl_SOURCES = client/main.c \
			client/adapter.c \
			client/agent.h client/agent.c \
			client/agent-manager.h client/agent-manager.c \
			client/ad-hoc.c \
			client/ap.c \
			client/command.h client/command.c \
			client/dbus-proxy.h client/dbus-proxy.c \
			client/device.h client/device.c \
			client/display.h client/display.c \
			client/known-networks.c \
			client/network.h client/network.c \
			client/properties.h client/properties.c \
			client/wsc.c client/station.c \
			client/diagnostic.c client/diagnostic.h \
			client/daemon.c client/daemon.h \
			client/dpp.c client/dpp-pkex.c \
			client/station-debug.c \
			client/bss.c \
			src/util.c src/util.h \
			src/band.c src/band.h

client_iwctl_LDADD = $(ell_ldadd) $(client_ldadd)

if MANUAL_PAGES
man_MANS += client/iwctl.1
endif
endif

if MONITOR
bin_PROGRAMS += monitor/iwmon

monitor_iwmon_SOURCES = monitor/main.c linux/nl80211.h \
					monitor/nlmon.h monitor/nlmon.c \
					monitor/pcap.h monitor/pcap.c \
					monitor/display.h monitor/display.c \
					src/ie.h src/ie.c \
					src/wscutil.h src/wscutil.c \
					src/mpdu.h src/mpdu.c \
					src/util.h src/util.c \
					src/crypto.h src/crypto.c \
					src/watchlist.h src/watchlist.c \
					src/eapolutil.h src/eapolutil.c \
					src/nl80211cmd.h src/nl80211cmd.c \
					src/p2putil.c src/p2putil.h \
					src/anqputil.h src/anqputil.c \
					src/band.h src/band.c
monitor_iwmon_LDADD = $(ell_ldadd)

if MANUAL_PAGES
man_MANS += monitor/iwmon.1
endif
endif

if WIRED
libexec_PROGRAMS += wired/ead

wired_ead_SOURCES = wired/main.c wired/ethdev.h wired/ethdev.c \
				wired/network.h wired/network.c \
				wired/dbus.h wired/dbus.c \
				src/module.h src/module.c \
				src/band.h src/band.c \
				$(eap_sources)
wired_ead_LDADD = $(ell_ldadd)
wired_ead_DEPENDENCIES = $(ell_dependencies)

if DBUS_POLICY
dist_dbus_data_DATA += wired/ead-dbus.conf
endif

if SYSTEMD_SERVICE
wired_ead_DEPENDENCIES += wired/ead.service

systemd_unit_DATA += wired/ead.service
dbus_bus_DATA += wired/net.connman.ead.service
endif

if MANUAL_PAGES
man_MANS += wired/ead.8
endif
endif

if DAEMON
noinst_PROGRAMS += tools/probe-req tools/iwd-decrypt-profile

tools_probe_req_SOURCES = tools/probe-req.c src/mpdu.h src/mpdu.c \
					src/ie.h src/ie.c \
					src/nl80211util.h src/nl80211util.c \
					src/util.h src/util.c \
					src/common.h src/common.c \
					src/band.h src/band.c
tools_probe_req_LDADD = $(ell_ldadd)

tools_iwd_decrypt_profile_SOURCES = tools/iwd-decrypt-profile.c \
					src/common.h src/common.c \
					src/crypto.h src/crypto.c \
					src/storage.h src/storage.c
tools_iwd_decrypt_profile_LDADD = ${ell_ldadd}
endif

if HWSIM
bin_PROGRAMS += tools/hwsim

tools_hwsim_SOURCES = tools/hwsim.c src/mpdu.h \
					src/util.h src/util.c \
					src/nl80211cmd.h src/nl80211cmd.c \
					src/nl80211util.h src/nl80211util.c \
					src/storage.h src/storage.c \
					src/common.h src/common.c \
					src/band.h src/band.c \
					src/ie.h src/ie.c \
					src/crypto.h src/crypto.c
tools_hwsim_LDADD = $(ell_ldadd)

if DBUS_POLICY
dist_dbus_data_DATA += tools/hwsim-dbus.conf
endif

if MANUAL_PAGES
man_MANS += tools/hwsim.1
endif
endif

unit_tests =

if DAEMON
unit_tests += unit/test-cmac-aes \
		unit/test-hmac-md5 unit/test-hmac-sha1 unit/test-hmac-sha256 \
		unit/test-prf-sha1 unit/test-kdf-sha256 \
		unit/test-crypto unit/test-eapol unit/test-mpdu \
		unit/test-ie unit/test-util unit/test-ssid-security \
		unit/test-arc4 unit/test-wsc unit/test-eap-mschapv2 \
		unit/test-eap-sim unit/test-sae unit/test-p2p unit/test-band \
		unit/test-dpp unit/test-json unit/test-nl80211util
endif

if CLIENT
unit_tests += unit/test-client
endif

if MAINTAINER_MODE
noinst_PROGRAMS += $(unit_tests)
endif

if DAEMON
unit_test_eap_sim_SOURCES = unit/test-eap-sim.c \
		src/crypto.h src/crypto.c src/simutil.h src/simutil.c \
		src/ie.h src/ie.c \
		src/watchlist.h src/watchlist.c \
		src/eapol.h src/eapol.c \
		src/eapolutil.h src/eapolutil.c \
		src/handshake.h src/handshake.c \
		src/eap.h src/eap.c src/eap-private.h \
		src/util.h src/util.c \
		src/simauth.h src/simauth.c \
		src/erp.h src/erp.c \
		src/band.h src/band.c \
		src/eap-sim.c
unit_test_eap_sim_LDADD = $(ell_ldadd)

unit_test_cmac_aes_SOURCES = unit/test-cmac-aes.c \
					src/crypto.h src/crypto.c
unit_test_cmac_aes_LDADD = $(ell_ldadd)

unit_test_arc4_SOURCES = unit/test-arc4.c \
					src/crypto.h src/crypto.c
unit_test_arc4_LDADD = $(ell_ldadd)

unit_test_hmac_md5_SOURCES = unit/test-hmac-md5.c \
					src/crypto.h src/crypto.c
unit_test_hmac_md5_LDADD = $(ell_ldadd)

unit_test_hmac_sha1_SOURCES = unit/test-hmac-sha1.c \
					src/crypto.h src/crypto.c
unit_test_hmac_sha1_LDADD = $(ell_ldadd)

unit_test_hmac_sha256_SOURCES = unit/test-hmac-sha256.c \
					src/crypto.h src/crypto.c
unit_test_hmac_sha256_LDADD = $(ell_ldadd)

unit_test_prf_sha1_SOURCES = unit/test-prf-sha1.c \
					src/crypto.h src/crypto.c
unit_test_prf_sha1_LDADD = $(ell_ldadd)

unit_test_kdf_sha256_SOURCES = unit/test-kdf-sha256.c \
					src/crypto.h src/crypto.c
unit_test_kdf_sha256_LDADD = $(ell_ldadd)

unit_test_ie_SOURCES = unit/test-ie.c src/ie.h src/ie.c
unit_test_ie_LDADD = $(ell_ldadd)

unit_test_band_SOURCES = unit/test-band.c src/band.h src/band.c src/netdev.h \
					src/ie.h src/ie.c
unit_test_band_LDADD = $(ell_ldadd)

unit_test_crypto_SOURCES = unit/test-crypto.c \
				src/crypto.h src/crypto.c
unit_test_crypto_LDADD = $(ell_ldadd)

unit_test_mpdu_SOURCES = unit/test-mpdu.c \
				src/mpdu.h src/mpdu.c \
				src/ie.h src/ie.c
unit_test_mpdu_LDADD = $(ell_ldadd)

unit_test_eapol_SOURCES = unit/test-eapol.c \
				src/crypto.h src/crypto.c \
				src/ie.h src/ie.c \
				src/watchlist.h src/watchlist.c \
				src/eapol.h src/eapol.c \
				src/eapolutil.h src/eapolutil.c \
				src/handshake.h src/handshake.c \
				src/eap.h src/eap.c src/eap-private.h \
				src/eap-tls.c src/eap-ttls.c \
				src/eap-md5.c src/util.c \
				src/eap-tls-common.h src/eap-tls-common.c \
				src/erp.h src/erp.c \
				src/band.h src/band.c \
				src/mschaputil.h src/mschaputil.c
unit_test_eapol_LDADD = $(ell_ldadd)
unit_test_eapol_DEPENDENCIES = $(ell_dependencies) \
				unit/cert-server.pem \
				unit/cert-server-key-pkcs8.pem \
				unit/cert-client.pem \
				unit/cert-client-key-pkcs8.pem \
				unit/tls-settings.8021x

unit_test_util_SOURCES = src/util.h src/util.c src/band.c src/band.h \
				unit/test-util.c
unit_test_util_LDADD = $(ell_ldadd)

unit_test_ssid_security_SOURCES = unit/test-ssid-security.c src/ie.h src/ie.c \
				src/common.h src/common.c
unit_test_ssid_security_LDADD = $(ell_ldadd)

unit_test_wsc_SOURCES = unit/test-wsc.c src/wscutil.h src/wscutil.c \
				src/crypto.h src/crypto.c \
				src/ie.h src/ie.c \
				src/watchlist.h src/watchlist.c \
				src/eapol.h src/eapol.c \
				src/eapolutil.h src/eapolutil.c \
				src/handshake.h src/handshake.c \
				src/eap.h src/eap.c src/eap-private.h \
				src/util.h src/util.c \
				src/erp.h src/erp.c \
				src/band.h src/band.c \
				src/eap-wsc.h src/eap-wsc.c
unit_test_wsc_LDADD = $(ell_ldadd)

unit_test_eap_mschapv2_SOURCES = src/eap-mschapv2.h src/eap-mschapv2.c \
				src/eap.c src/eap.h src/eap-private.h \
				src/mschaputil.h src/mschaputil.c \
				unit/test-eap-mschapv2.c
unit_test_eap_mschapv2_LDADD = $(ell_ldadd)

unit_test_sae_SOURCES = unit/test-sae.c \
				src/sae.h src/sae.c \
				src/crypto.h src/crypto.c \
				src/ie.h src/ie.c \
				src/handshake.h src/handshake.c \
				src/erp.h src/erp.c \
				src/band.h src/band.c \
				src/util.h src/util.c \
				src/mpdu.h src/mpdu.c
unit_test_sae_LDADD = $(ell_ldadd)
unit_test_sae_LDFLAGS = -Wl,-wrap,l_ecc_supported_ike_groups

unit_test_p2p_SOURCES = unit/test-p2p.c src/wscutil.h src/wscutil.c \
				src/crypto.h src/crypto.c \
				src/ie.h src/ie.c \
				src/util.h src/util.c \
				src/p2putil.h src/p2putil.c \
				src/band.h src/band.c
unit_test_p2p_LDADD = $(ell_ldadd)

unit_test_dpp_SOURCES = unit/test-dpp.c src/dpp-util.h src/dpp-util.c \
				src/band.h src/band.c \
				src/util.h src/util.c src/crypto.h \
				src/crypto.c src/json.h src/json.c
unit_test_dpp_LDADD = $(ell_ldadd)

unit_test_json_SOURCES = unit/test-json.c src/json.h src/json.c shared/jsmn.h
unit_test_json_LDADD = $(ell_ldadd)

unit_test_nl80211util_SOURCES = unit/test-nl80211util.c \
				src/nl80211util.h src/nl80211util.c \
				src/band.h src/band.c \
				src/ie.h src/ie.c \
				src/util.h src/util.c
unit_test_nl80211util_LDADD = $(ell_ldadd)
endif

if CLIENT
unit_test_client_SOURCES = unit/test-client.c \
				client/adapter.c \
				client/agent.h client/agent.c \
				client/agent-manager.h client/agent-manager.c \
				client/command.h client/command.c \
				client/dbus-proxy.h client/dbus-proxy.c \
				client/display.h client/display.c \
				client/network.h client/network.c \
				client/properties.h client/properties.c
unit_test_client_LDADD = $(ell_ldadd) $(client_ldadd)
endif

TESTS = $(unit_tests)

EXTRA_DIST = src/genbuiltin src/iwd.service.in src/net.connman.iwd.service \
			wired/ead.service.in wired/net.connman.ead.service \
			src/80-iwd.link src/pkcs8.conf unit/gencerts.cnf \
			doc/main.conf \
			$(manual_pages) $(patsubst %.1,%.rst, \
					$(patsubst %.5,%.rst, \
					$(patsubst %.8,%.rst,$(manual_pages))))

AM_CFLAGS = $(ell_cflags) $(client_cflags) -fvisibility=hidden \
				-DUNITDIR=\""$(top_srcdir)/unit/"\" \
				-DCERTDIR=\""$(top_builddir)/unit/"\"

if MAINTAINER_MODE
AM_CFLAGS += -DHAVE_PKCS8_SUPPORT
endif

CLEANFILES = src/iwd.service wired/ead.service

DISTCHECK_CONFIGURE_FLAGS = --disable-dbus-policy --disable-systemd-service \
				--enable-ofono \
				--enable-wired \
				--enable-hwsim \
				--enable-tools

DISTCLEANFILES = $(BUILT_SOURCES) $(unit_tests) $(manual_pages)

MAINTAINERCLEANFILES = Makefile.in configure config.h.in aclocal.m4

true_redirect_openssl = 2>&1
false_redirect_openssl = 2>/dev/null

unit/cert-ca-key.pem:
	$(AM_V_GEN)openssl genrsa -out $@ 2048 $($(AM_V_P)_redirect_openssl)

unit/cert-ca.pem: unit/cert-ca-key.pem unit/gencerts.cnf
	$(AM_V_GEN)openssl req -x509 -new -nodes -extensions ca_ext \
			-config $(srcdir)/unit/gencerts.cnf \
			-subj '/O=International Union of Example Organizations/CN=Certificate issuer guy/emailAddress=ca@mail.example' \
			-key $< -sha256 -days 10000 -out $@

unit/cert-server-key.pem:
	$(AM_V_GEN)openssl genrsa -out $@ $($(AM_V_P)_redirect_openssl)

unit/cert-server-key-pkcs8.pem: unit/cert-server-key.pem
	$(AM_V_GEN)openssl pkcs8 -topk8 -nocrypt -in $< -out $@

unit/cert-server.csr: unit/cert-server-key.pem unit/gencerts.cnf
	$(AM_V_GEN)openssl req -new -extensions cert_ext \
			-config $(srcdir)/unit/gencerts.cnf \
			-subj '/O=Foo Example Organization/CN=Foo Example Organization/emailAddress=foo@mail.example' \
			-key $< -out $@

unit/cert-server.pem: unit/cert-server.csr unit/cert-ca.pem unit/gencerts.cnf
	$(AM_V_GEN)openssl x509 -req -extensions server_ext \
			-extfile $(srcdir)/unit/gencerts.cnf \
			-in $< -CA $(builddir)/unit/cert-ca.pem \
			-CAkey $(builddir)/unit/cert-ca-key.pem \
			-CAserial $(builddir)/unit/cert-ca.srl \
			-CAcreateserial -sha256 -days 10000 -out $@ $($(AM_V_P)_redirect_openssl)

unit/cert-client-key.pem:
	$(AM_V_GEN)openssl genrsa -out $@ $($(AM_V_P)_redirect_openssl)

unit/cert-client-key-pkcs8.pem: unit/cert-client-key.pem
	$(AM_V_GEN)openssl pkcs8 -topk8 -nocrypt -in $< -out $@

unit/cert-client.csr: unit/cert-client-key.pem unit/gencerts.cnf
	$(AM_V_GEN)openssl req -new -extensions cert_ext \
			-config $(srcdir)/unit/gencerts.cnf \
			-subj '/O=Bar Example Organization/CN=Bar Example Organization/emailAddress=bar@mail.example' \
			-key $< -out $@

unit/cert-client.pem: unit/cert-client.csr unit/cert-ca.pem unit/gencerts.cnf
	$(AM_V_GEN)openssl x509 -req -extensions cert_ext \
			-extfile $(srcdir)/unit/gencerts.cnf \
			-in $< -CA $(builddir)/unit/cert-ca.pem \
			-CAkey $(builddir)/unit/cert-ca-key.pem \
			-CAserial $(builddir)/unit/cert-ca.srl \
			-CAcreateserial -sha256 -days 10000 -out $@ $($(AM_V_P)_redirect_openssl)

unit/tls-settings.8021x: unit/cert-ca.pem unit/cert-client.pem unit/cert-client-key-pkcs8.pem
	$(AM_V_GEN) \
	$(file >$@,[Security]) \
	$(file >>$@,EAP-Method=TLS) \
	$(file >>$@,EAP-Identity=abc@example.com) \
	$(file >>$@,EAP-TLS-CACert=embed:ca_cert) \
	$(file >>$@,EAP-TLS-ClientCert=embed:client_cert) \
	$(file >>$@,EAP-TLS-ClientKey=embed:client_key) \
	$(file >>$@,[@pem@ca_cert]) \
	$(shell cat unit/cert-ca.pem >> $@) \
	$(file >>$@,[@pem@client_cert]) \
	$(shell cat unit/cert-client.pem >> $@) \
	$(file >>$@,[@pem@client_key]) \
	$(shell cat unit/cert-client-key-pkcs8.pem >> $@)

BUILT_SOURCES = $(ell_built_sources) src/builtin.h

ell/shared: Makefile
	$(AM_V_at)$(MKDIR_P) ell
	$(AM_V_GEN)for f in $(ell_shared) ; do \
		if [ ! -f $$f ] ; then \
			$(LN_S) -t ell -f $(abs_srcdir)/../ell/$$f ; \
		fi \
	done > $@

ell/internal: Makefile
	$(AM_V_at)$(MKDIR_P) ell
	$(AM_V_GEN)for f in $(ell_headers) $(ell_sources) ; do \
		if [ ! -f $$f ] ; then \
			$(LN_S) -t ell -f $(abs_srcdir)/../ell/$$f ; \
		fi \
	done > $@

ell/ell.h: Makefile
	$(AM_V_at)$(MKDIR_P) ell
	$(AM_V_at)echo -n > $@
	$(AM_V_GEN)for f in $(ell_headers) ; do \
		echo "#include <$$f>" >> $@ ; \
	done

SED_PROCESS = $(AM_V_GEN)$(MKDIR_P) $(dir $@) && $(SED) \
		-e 's,@libexecdir\@,$(libexecdir),g' \
		< $< > $@

if RUN_RST2MAN
RST2MAN_PROCESS = $(AM_V_GEN)$(MKDIR_P) $(dir $@) && \
			$(RST2MAN) --strict --no-raw \
			--no-generator --no-datestamp $< $@
else
RST2MAN_PROCESS = $(AM_V_GEN)test -f $@ || \
		{ echo "Generated manual page $@ does not exist"; false; }
endif

%.service: %.service.in Makefile
	$(SED_PROCESS)

%.1: %.rst Makefile
	$(RST2MAN_PROCESS)

%.5: %.rst Makefile
	$(RST2MAN_PROCESS)

%.7: %.rst Makefile
	$(RST2MAN_PROCESS)

%.8: %.rst Makefile
	$(RST2MAN_PROCESS)

install-data-local:
if !SYSTEMD_SERVICE
if DAEMON
	$(MKDIR_P) -m 700 $(DESTDIR)$(daemon_storagedir)
endif
if WIRED
	$(MKDIR_P) -m 700 $(DESTDIR)$(wired_storagedir)
endif
endif

gcov-clean:
if GCOV
	-$(LCOV) --quiet --directory $(builddir) -z
	-rm -rf "$(builddir)/iwd-coverage.info" "$(builddir)/gcov"
	-find . -name "*.gcda" -o -name "*.gcov" -o -name "*.gcno" -delete
endif

clean-local: gcov-clean
	-rm -f unit/cert-*.pem unit/cert-*.csr unit/cert-*.srl unit/*-settings.8021x

maintainer-clean-local:
	-rm -rf build-aux ell

gcov-report:
if GCOV
	$(LCOV) --quiet --directory $(builddir) --capture --output-file "iwd-coverage.info"
	LANG=C $(GENHTML) --quiet --prefix $(builddir) --output-directory "$(builddir)/gcov" --title "iwd Code Coverage" --legend "$(builddir)/iwd-coverage.info"
endif

src/builtin.h: src/genbuiltin config.status
	$(AM_V_at)$(MKDIR_P) $(@D)
	$(AM_V_GEN)$(srcdir)/src/genbuiltin $(builtin_modules) > $@
