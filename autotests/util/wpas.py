#!/usr/bin/python3
import os
import socket
import shutil
from gi.repository import GLib
from config import ctx
from unittest import SkipTest

import binascii

from utils import Process

ctrl_count = 0

class Wpas:
    io_watch = None
    sockets = {}
    wpa_supplicant = None
    cleanup_paths = []

    def _start_wpas(self, config_name=None, p2p=False):
        if not shutil.which('wpa_supplicant'):
            print('wpa_supplicant not found, skipping test')
            raise SkipTest

        main_interface = None
        for interface in ctx.wpas_interfaces:
            if config_name is None or interface.config == config_name:
                if main_interface is not None:
                    raise Exception('More than one wpa_supplicant interface matches given config')
                main_interface = interface

        if main_interface is None:
            raise Exception('No matching wpa_supplicant interface')

        ifname = main_interface.name
        if p2p:
            ifname = 'p2p-dev-' + ifname

        self.interface = main_interface
        self.ifname = ifname
        self.config_path = '/tmp/' + self.interface.config
        self.config = self._get_config()
        self.socket_path = self.config['ctrl_interface']

        cmd = ['wpa_supplicant', '-i', self.interface.name, '-c', self.config_path]
        if Process.is_verbose('wpa_supplicant-dbg'):
            cmd += ['-d']

        self.wpa_supplicant = ctx.start_process(cmd)

        self.sockets = {}
        self.io_watch = GLib.io_add_watch(self._get_socket(), GLib.IO_IN, self._handle_data_in)

        self.p2p_peers = {}
        self.p2p_go_neg_requests = {}
        self.p2p_clients = {}
        self.p2p_group = None

        self._rx_data = []
        self._ctrl_request('ATTACH')
        self.wait_for_event('OK')

    def __init__(self, *args, **kwargs):
        self._start_wpas(*args, **kwargs)

    def _get_config(self):
        f = open(self.config_path)
        lines = f.readlines()
        f.close()
        return dict([[v.strip() for v in kv] for kv in [l.split('#', 1)[0].split('=', 1) for l in lines] if len(kv) == 2])

    def _check_event(self, event):
        if not event and len(self._rx_data) >= 1:
            return self._rx_data[0]

        for e in self._rx_data:
            if event in e:
                return self._rx_data

        return False

    def wait_for_event(self, event, timeout=10):
        self._rx_data = []
        return ctx.non_block_wait(self._check_event, timeout, event)

    def wait_for_result(self, timeout=10):
        self._rx_data = []
        return self.wait_for_event(None, timeout=timeout)

    def _event_parse(self, line):
        # Unescape event parameter values in '', other escaping rules not implemented
        key = None
        value = ''
        count = 0
        quoted = False
        event = {}

        def handle_eow():
            nonlocal key, value, count, event
            if count == 0:
                key = 'event'
            elif key is None:
                if not value:
                    return
                key = 'arg' + str(count)
            event[key] = value
            key = None
            value = ''
            count += 1

        for ch in line:
            if ch == '\'':
                quoted = not quoted
            elif quoted:
                value += ch
            elif ch == '=' and key is None:
                key = value
                value = ''
            elif ch in ' \n':
                handle_eow()
            else:
                value += ch
        handle_eow()
        return event

    def _handle_data_in(self, sock, *args):
        newdata = sock.recv(4096)
        if len(newdata) == 0:
            raise Exception('Wpa_s control socket error')

        decoded = newdata.decode('utf-8')
        if len(decoded) >= 3 and decoded[0] == '<' and decoded[2] == '>':
            decoded = decoded[3:]
        while len(decoded) and decoded[-1] == '\n':
            decoded = decoded[:-1]

        self._rx_data.append(decoded)

        event = self._event_parse(decoded)
        if event['event'] == 'P2P-DEVICE-FOUND':
            event.pop('event')
            event.pop('arg1')
            self.p2p_peers[event['p2p_dev_addr']] = event
        elif event['event'] == 'P2P-DEVICE-LOST':
            del self.p2p_peers[event['p2p_dev_addr']]
        elif event['event'] == 'P2P-GO-NEG-REQUEST':
            event.pop('event')
            event['p2p_dev_addr'] = event.pop('arg1')
            self.p2p_go_neg_requests[event['p2p_dev_addr']] = event
        elif event['event'] == 'P2P-GO-NEG-SUCCESS':
            event.pop('event')
            addr = event.pop('peer_dev')
            event['success'] = True
            event['p2p_dev_addr'] = addr

            if addr in self.p2p_go_neg_requests:
                self.p2p_go_neg_requests[addr].update(event)
            else:
                self.p2p_go_neg_requests[addr] = event
        elif event['event'] == 'AP-STA-CONNECTED':
            event.pop('event')
            addr = event.pop('arg1')
            self.p2p_clients[addr] = event
        elif event['event'] == 'AP-STA-DISCONNECTED':
            addr = event.pop('arg1')
            del self.p2p_clients[addr]
        elif event['event'] == 'P2P-GROUP-STARTED':
            event.pop('event')
            event['ifname'] = event.pop('arg1')
            event['role'] = event.pop('arg2')
            self.p2p_group = event
        elif event['event'] == 'P2P-GROUP-REMOVED':
            self.p2p_group = None

        return True

    def _ctrl_request(self, command, ifname=None):
        if type(command) is str:
            command = str.encode(command)

        self._get_socket(ifname).send(bytes(command))

    def _get_socket(self, ifname=None):
        global ctrl_count

        if ifname is None:
            ifname = self.ifname

        if ifname in self.sockets:
            return self.sockets[ifname]

        local_path = '/tmp/wpas_' + str(os.getpid()) + '_' + str(ctrl_count)
        ctrl_count = ctrl_count + 1
        remote_path = self.socket_path + '/' + ifname

        self.wpa_supplicant.wait_for_socket(remote_path, 2)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock.bind(local_path)
        self.cleanup_paths.append(local_path)
        sock.connect(remote_path)
        self.cleanup_paths.append(remote_path)

        self.sockets[ifname] = sock
        return sock

    # Normal find phase with listen and active scan states
    def p2p_find(self):
        self._rx_data = []
        self._ctrl_request('P2P_SET disc_int 2 3 300')
        self.wait_for_event('OK')
        self._rx_data = []
        self._ctrl_request('P2P_FIND type=social')
        self.wait_for_event('OK')

    # Like p2p_find but uses only listen states
    def p2p_listen(self):
        self._rx_data = []
        self._ctrl_request('P2P_LISTEN')
        self.wait_for_event('OK')

    # Stop a p2p_find or p2p_listen
    def p2p_stop_find_listen(self):
        self._rx_data = []
        self._ctrl_request('P2P_STOP_FIND')
        self.wait_for_event('OK')

    def p2p_connect(self, peer, pin=None, go_intent=None):
        self._rx_data = []
        self._ctrl_request('P2P_CONNECT ' + peer['p2p_dev_addr'] + ' ' + ('pbc' if pin is None else pin) +
                        ('' if go_intent is None else ' go_intent=' + str(go_intent)))
        self.wait_for_event('OK')

    def p2p_accept_go_neg_request(self, request, pin=None, go_intent=None):
        self._rx_data = []
        self._ctrl_request('P2P_CONNECT ' + request['p2p_dev_addr'] + ' ' + ('pbc' if pin is None else pin) +
                        ('' if go_intent is None else ' go_intent=' + str(go_intent)))
        self.wait_for_event('OK')

    # Pre-accept the next GO Negotiation Request from this peer to avoid the extra Respone + Request frames
    def p2p_authorize(self, peer, pin=None, go_intent=None):
        self._rx_data = []
        self._ctrl_request('P2P_CONNECT ' + peer['p2p_dev_addr'] + ' ' + ('pbc' if pin is None else pin) +
                        ('' if go_intent is None else ' go_intent=' + str(go_intent)) + ' auth')
        self.wait_for_event('OK')

    def p2p_set(self, key, value, **kwargs):
        self._ctrl_request('P2P_SET ' + key + ' ' + value, **kwargs)

    def set(self, key, value, **kwargs):
        self._ctrl_request('SET ' + key + ' ' + value, **kwargs)

    def dpp_enrollee_start(self, uri=None, oper_and_channel=None):
        if not oper_and_channel:
            oper_and_channel = '81/1'

        self._rx_data = []
        self._ctrl_request('DPP_BOOTSTRAP_GEN type=qrcode chan=%s' % oper_and_channel)
        self._dpp_qr_id = self.wait_for_result()
        self._ctrl_request('DPP_BOOTSTRAP_GET_URI %s' % self._dpp_qr_id)
        self._dpp_uri = self.wait_for_result()

        print("DPP Enrollee QR: %s" % self._dpp_uri)

        if uri:
            self._rx_data = []
            self._ctrl_request('DPP_QR_CODE ' + uri)
            self._dpp_qr_id = self.wait_for_result()
            self._rx_data = []
            self._ctrl_request('DPP_AUTH_INIT peer=%s role=enrollee' % self._dpp_qr_id)
        else:
            self._ctrl_request('DPP_CHIRP own=%s iter=100' % self._dpp_qr_id)

        return self._dpp_uri

    def dpp_configurator_create(self, uri=None):
        self._rx_data = []
        self._ctrl_request('DPP_CONFIGURATOR_ADD')
        self._dpp_conf_id = self.wait_for_result()
        while not self._dpp_conf_id.isnumeric():
            self._dpp_conf_id = self.wait_for_result()

        if not uri:
            print("DPP Configurator ID: %s", self._dpp_conf_id)
            return

        self._rx_data = []
        self._ctrl_request('DPP_QR_CODE ' + uri)
        self._dpp_qr_id = self.wait_for_result()
        while not self._dpp_conf_id.isnumeric():
            self._dpp_qr_id = self.wait_for_result()

        print("DPP Configurator ID: %s. DPP QR ID: %s" % (self._dpp_conf_id, self._dpp_qr_id))

    def dpp_configurator_start(self, ssid, passphrase, freq=None):
        ssid = binascii.hexlify(ssid.encode()).decode()
        passphrase = binascii.hexlify(passphrase.encode()).decode()

        cmd = 'DPP_AUTH_INIT peer=%s conf=sta-psk ssid=%s pass=%s ' % (self._dpp_qr_id, ssid, passphrase)

        if freq:
            cmd += 'neg_freq=%u ' % freq

        self._rx_data = []
        self._ctrl_request(cmd)
        self.wait_for_event('DPP-AUTH-SUCCESS', timeout=30)
        self.wait_for_event('DPP-CONF-SENT')

    def dpp_bootstrap_gen(self, type='qrcode', curve=None):
        cmd = f'DPP_BOOTSTRAP_GEN type={type}'

        if curve:
            cmd += f' curve={curve}'

        self._rx_data = []
        self._ctrl_request(cmd)
        self._dpp_id = self.wait_for_result()

    def dpp_pkex_add(self, code, identifier=None, version=None, initiator=False, role=None):
        cmd = f'DPP_PKEX_ADD own={self._dpp_id}'

        if identifier:
            cmd += f' identifier={identifier}'

        if initiator:
            cmd += f' init=1'

        if version:
            cmd += f' ver={version}'

        if role:
            cmd += f' role={role}'

        cmd += f' code={code}'

        self._rx_data = []
        self._ctrl_request(cmd)

    def dpp_listen(self, freq):
        self._rx_data = []
        self._ctrl_request(f'DPP_LISTEN {freq}')

    def dpp_configurator_remove(self):
        self._ctrl_request('DPP_CONFIGURATOR_REMOVE *')
        self.wait_for_result()
        self._ctrl_request('DPP_BOOTSTRAP_REMOVE *')
        self.wait_for_result()

    def disconnect(self):
        self._ctrl_request('DISCONNECT')

    # Probably needed: remove references to self so that the GC can call __del__ automatically
    def clean_up(self):
        if self.io_watch is not None:
            GLib.source_remove(self.io_watch)
            self.io_watch = None
        for ifname in self.sockets:
            self.sockets[ifname].close()
        self.sockets = {}
        if self.wpa_supplicant is not None:
            ctx.stop_process(self.wpa_supplicant)
            self.wpa_supplicant = None
        for path in self.cleanup_paths:
            if os.path.exists(path):
                os.remove(path)
        self.cleanup_paths = []

    def __del__(self):
        self.clean_up()
