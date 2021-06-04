#!/usr/bin/python3
import os
import socket
from gi.repository import GLib
from config import ctx

ctrl_count = 0

class Wpas:
    def _start_wpas(self, config_name=None, p2p=False):
        global ctrl_count

        main_interface = None
        for interface in ctx.wpas_interfaces:
            if config_name is None or interface.config == config_name:
                if main_interface is not None:
                    raise Exception('More than was wpa_supplicant interface matches given config')
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
        self.io_watch = None

        cmd = ['wpa_supplicant', '-i', self.interface.name, '-c', self.config_path]
        if ctx.is_verbose('wpa_supplicant-dbg'):
            cmd += ['-d']

        self.wpa_supplicant = ctx.start_process(cmd)

        self.local_ctrl = '/tmp/wpas_' + str(os.getpid()) + '_' + str(ctrl_count)
        ctrl_count = ctrl_count + 1
        self.ctrl_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.ctrl_sock.bind(self.local_ctrl)

        self.remote_ctrl = self.socket_path + '/' + self.ifname
        self.wpa_supplicant.wait_for_socket(self.remote_ctrl, 2)
        self.ctrl_sock.connect(self.remote_ctrl)
        self.io_watch = GLib.io_add_watch(self.ctrl_sock, GLib.IO_IN, self._handle_data_in)

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

    def wait_for_event(self, event, timeout=10):
        self._wait_timed_out = False

        def wait_timeout_cb():
            self._wait_timed_out = True
            return False

        timeout = GLib.timeout_add_seconds(timeout, wait_timeout_cb)
        context = ctx.mainloop.get_context()

        while True:
            context.iteration(may_block=True)

            if event in self._rx_data:
                GLib.source_remove(timeout)
                return self._rx_data

            if self._wait_timed_out:
                raise TimeoutError('waiting for wpas event timed out')

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
                if key is not None or not value:
                    raise Exception('Bad event name')
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
            self.p2p_group = event
        elif event['event'] == 'P2P-GROUP-REMOVED':
            self.p2p_group = None

        return True

    def _ctrl_request(self, command, timeout=10):
        if type(command) is str:
            command = str.encode(command)

        self.ctrl_sock.send(bytes(command))

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

    # Probably needed: remove references to self so that the GC can call __del__ automatically
    def clean_up(self):
        if self.io_watch is not None:
            GLib.source_remove(self.io_watch)
            self.io_watch = None
        if self.wpa_supplicant is not None:
            ctx.stop_process(self.wpa_supplicant)
            self.wpa_supplicant = None

    def _stop_wpas(self):
        self.clean_up()
        if self.ctrl_sock:
            self.ctrl_sock.close()
            self.ctrl_sock = None
        if os.path.exists(self.remote_ctrl):
            os.remove(self.remote_ctrl)
        if os.path.exists(self.local_ctrl):
            os.remove(self.local_ctrl)

    def __del__(self):
        self._stop_wpas()
