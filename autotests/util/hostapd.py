#!/usr/bin/python3
import os, os.path
import re
import socket
import select
import time
from gi.repository import GLib
from weakref import WeakValueDictionary
from config import ctx

chan_freq_map = [
    None,
    2412,
    2417,
    2422,
    2427,
    2432,
    2437,
    2442,
    2447,
    2452,
    2457,
    2462,
    2467,
    2472,
    2484
]

ctrl_count = 0
mainloop = GLib.MainLoop()

class HostapdCLI(object):
    _instances = WeakValueDictionary()

    def __new__(cls, config=None, *args, **kwargs):
        hapd = ctx.get_hapd_instance(config)

        if not config:
            config = hapd.config

        if not config in cls._instances.keys():
            obj = object.__new__(cls, *args, **kwargs)
            obj._initialized = False

            cls._instances[config] = obj

        return cls._instances[config]

    def __init__(self, config=None, *args, **kwargs):
        global ctrl_count

        if self._initialized:
            return

        self._initialized = True
        self.ctrl_sock = None

        if not ctx.hostapd:
            raise Exception("No hostapd instances are configured")

        if not config and sum([len(hapd.instances) for hapd in ctx.hostapd]) > 1:
            raise Exception('config must be provided if more than one hostapd instance exists')

        hapd = ctx.get_hapd_instance(config)

        self.interface = hapd.intf
        self.config = hapd.config

        if not self.interface:
            raise Exception('config %s not found' % config)

        self.ifname = self.interface.name
        self.socket_path = os.path.dirname(self.interface.ctrl_interface)

        self.cmdline = ['hostapd_cli', '-p', self.socket_path, '-i', self.ifname]

        self.local_ctrl = '/tmp/hostapd_' + str(os.getpid()) + '_' + \
                            str(ctrl_count)
        self.ctrl_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.ctrl_sock.bind(self.local_ctrl)

        self.ctrl_sock.connect(self.socket_path + '/' + self.ifname)

        self.events = []
        self.io_watch = GLib.io_add_watch(self.ctrl_sock, GLib.IO_IN, self._handle_data_in)

        if 'OK' not in self._ctrl_request('ATTACH'):
            raise Exception('ATTACH failed')

        ctrl_count = ctrl_count + 1

    def _handle_data_in(self, sock, *args):
        newdata = sock.recv(4096)

        decoded = newdata.decode('utf-8')
        if len(decoded) >= 3 and decoded[0] == '<' and decoded[2] == '>':
            decoded = decoded[3:]
        while len(decoded) and decoded[-1] == '\n':
            decoded = decoded[:-1]

        self.events.insert(0, decoded)

        return True

    def _poll_event(self, event, disallow):
        # Look through the list (most recent is first) until the even is found.
        # Once found consume this event and any older ones as to not
        # accidentally trigger a false positive later on.
        for idx, e in enumerate(self.events):
            for d in disallow:
                if d in e:
                    raise Exception('Event %s found while waiting for %s' % (d, event))
            if event in e:
                self.events = self.events[:idx]
                return e

        return False

    def wait_for_event(self, event, timeout=10, disallow=[]):
        if event == 'AP-ENABLED':
            if self.enabled:
                return 'AP-ENABLED'

        return ctx.non_block_wait(self._poll_event, timeout, event, disallow,
                                    exception=TimeoutError("waiting for event"))

    def _data_available(self):
        [r, w, e] = select.select([self.ctrl_sock], [], [])
        if r:
            return True
        return False

    def _ctrl_request(self, command, timeout=10):
        if type(command) is str:
            command = str.encode(command)

        self.ctrl_sock.send(bytes(command))

        ctx.non_block_wait(self._data_available, timeout,
                            exception=TimeoutError("waiting for control response"))

        return self.ctrl_sock.recv(4096).decode('utf-8')

    def __del__(self):
        if self.ctrl_sock:
            self.ctrl_sock.close()

        try:
            os.remove(self.local_ctrl)
        except:
            pass

    def set_value(self, key, value):
        cmd = self.cmdline + ['set', key, value]
        ctx.start_process(cmd).wait()

    def wps_push_button(self):
        ctx.start_process(self.cmdline + ['wps_pbc']).wait()

    def wps_pin(self, pin):
        cmd = self.cmdline + ['wps_pin', 'any', pin]
        ctx.start_process(cmd).wait()

    def deauthenticate(self, client_address):
        cmd = self.cmdline + ['deauthenticate', client_address]
        ctx.start_process(cmd).wait()

    def eapol_reauth(self, client_address):
        self.events = []
        cmd = 'EAPOL_REAUTH ' + client_address
        self.ctrl_sock.sendall(cmd.encode('utf-8'))
        self.wait_for_event('CTRL-EVENT-EAP-STARTED', disallow=['AP-STA-DISCONNECTED'])
        self.wait_for_event('CTRL-EVENT-EAP-SUCCESS', disallow=['AP-STA-DISCONNECTED'])

    def reload(self):
        # Seemingly all three commands needed for the instance to notice
        # interface's address change
        ctx.start_process(self.cmdline + ['reload']).wait()
        ctx.start_process(self.cmdline + ['disable']).wait()
        ctx.start_process(self.cmdline + ['enable']).wait()

    def disable(self):
        ctx.start_process(self.cmdline + ['disable']).wait()

    def list_sta(self):
        proc = ctx.start_process(self.cmdline + ['list_sta'])
        proc.wait()

        if not proc.out:
            return []

        return [line for line in proc.out.split('\n') if line]

    def set_neighbor(self, addr, ssid, nr):
        cmd = self.cmdline + ['set_neighbor', addr, 'ssid="%s"' % ssid, 'nr=%s' % nr]
        ctx.start_process(cmd).wait()

    def remove_neighbor(self, addr):
        cmd = self.cmdline + ['remove_neighbor', addr]
        ctx.start_process(cmd).wait()

    def send_bss_transition(self, device, nr_list, disassoc_imminent=True):
        # Send a BSS transition to a station (device). nr_list should be an
        # array of tuples containing the BSS address and neighbor report.
        # Parsing the neighbor report is a bit ugly but it makes it more
        # consistent with the set_neighbor() API, i.e. the same neighbor report
        # string could be used in both API's.
        pref = 1
        cmd = self.cmdline + ['bss_tm_req', device]

        if disassoc_imminent:
            cmd.append('disassoc_imminent=1')

        for i in nr_list:
            addr = i[0]
            nr = i[1]

            bss_info=str(int(nr[0:8], 16))
            op_class=str(int(nr[8:10], 16))
            chan_num=nr[10:12]
            phy_num=nr[14:16]

            cmd += ['pref=%s' % str(pref), 'neighbor=%s,%s,%s,%s,%s' % \
                        (addr, bss_info, op_class, chan_num, phy_num)]
            pref += 1

        proc = ctx.start_process(cmd)
        proc.wait()

        if 'OK' not in proc.out:
            raise Exception('BSS_TM_REQ failed, is hostapd built with CONFIG_WNM_AP=y?')

    def req_beacon(self, addr, request):
        '''
            Send a RRM Beacon request
        '''
        cmd = self.cmdline + ['req_beacon', addr, request]
        ctx.start_process(cmd).wait()

    def rekey(self, address=None):
        if address:
            cmd = 'REKEY_PTK %s' % address
            self.ctrl_sock.sendall(cmd.encode('utf-8'))
            self.events = []
            self.wait_for_event('EAPOL-4WAY-HS-COMPLETED', disallow=['AP-STA-DISCONNECTED'])
            return

        cmd = 'REKEY_GTK'
        self.ctrl_sock.sendall(cmd.encode('utf-8'))

    def resend_m3(self, address):
        cmd = 'RESEND_M3 %s' % address
        self.ctrl_sock.sendall(cmd.encode('utf-8'))

    def chan_switch(self, channel):
        if channel > len(chan_freq_map):
            raise Exception("Only 2.4GHz channels supported for chan_switch")

        cmd = self.cmdline + ['chan_switch', '50', str(chan_freq_map[channel])]
        ctx.start_process(cmd).wait()
        self.wait_for_event('AP-CSA-FINISHED')

    def _get_status(self):
        ret = {}

        cmd = self.cmdline + ['status']
        proc = ctx.start_process(cmd)
        proc.wait()
        status = proc.out.strip().split('\n')

        for kv in status:
            k, v = kv.split('=')
            ret[k] = v

        return ret

    @property
    def bssid(self):
        return self._get_status()['bssid[0]']

    @property
    def frequency(self):
        return int(self._get_status()['freq'])

    @property
    def enabled(self):
        return self._get_status()['state'] == 'ENABLED'

    def set_address(self, mac):
        os.system('ip link set dev %s down' % self.ifname)
        os.system('ip link set dev %s addr %s up' % (self.ifname, mac))

        self.reload()
        self.wait_for_event("AP-ENABLED")

    def _add_neighbors(self, *args, op_class=81):
        for hapd in args:
            status = hapd._get_status()

            ssid = status['ssid[0]']
            bssid = status['bssid[0]']
            channel = int(status['channel'])

            if (channel > 14 and op_class == 81):
                raise Exception("default add_neighbors assumes opclass 0x51!")

            channel = '{:02x}'.format(channel)
            oper_class = '{:02x}'.format(op_class)

            self.set_neighbor(bssid, ssid, '%s8f000000%s%s060603000000' %
                                (bssid.replace(':', ''), oper_class, channel))

    @classmethod
    def group_neighbors(cls, *args):
        for hapd in args:
            others = [h for h in args if h != hapd]

            hapd._add_neighbors(*others)
