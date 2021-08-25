#!/usr/bin/python3
import os, os.path
import re
import socket
import select
import time
from gi.repository import GLib
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
    _instances = {}

    def __new__(cls, config=None, *args, **kwargs):
        hapd = ctx.hostapd[config]

        if not config:
            config = hapd.config

        if not config in cls._instances.keys():
            cls._instances[config] = object.__new__(cls, *args, **kwargs)
            cls._instances[config]._initialized = False

        return cls._instances[config]

    def __init__(self, config=None, *args, **kwargs):
        global ctrl_count

        if self._initialized:
            return

        self._initialized = True
        self.ctrl_sock = None

        if not ctx.hostapd:
            raise Exception("No hostapd instances are configured")

        if not config and len(ctx.hostapd.instances) > 1:
            raise Exception('config must be provided if more than one hostapd instance exists')

        hapd = ctx.hostapd[config]

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

        if 'OK' not in self._ctrl_request('ATTACH'):
            raise Exception('ATTACH failed')

        ctrl_count = ctrl_count + 1

    def _poll_event(self, event):
        if not self._data_available(0.25):
            return False

        data = self.ctrl_sock.recv(4096).decode('utf-8')
        if event in data:
            return data

        return False

    def wait_for_event(self, event, timeout=10):
        return ctx.non_block_wait(self._poll_event, timeout, event,
                                    exception=TimeoutError("waiting for event"))

    def _data_available(self, timeout=2):
        [r, w, e] = select.select([self.ctrl_sock], [], [], timeout)
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

        HostapdCLI._instances[self.config] = None

        # Check if this is the final instance
        destroy = len([hapd for hapd in HostapdCLI._instances.values() if hapd is not None]) == 0
        if destroy:
            HostapdCLI._instances = {}

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
        cmd = 'IFNAME=' + self.ifname + ' EAPOL_REAUTH ' + client_address
        self.ctrl_sock.sendall(cmd.encode('utf-8'))

    def reload(self):
        # Seemingly all three commands needed for the instance to notice
        # interface's address change
        ctx.start_process(self.cmdline + ['reload']).wait()
        ctx.start_process(self.cmdline + ['disable']).wait()
        ctx.start_process(self.cmdline + ['enable']).wait()

    def list_sta(self):
        proc = ctx.start_process(self.cmdline + ['list_sta'])
        proc.wait()

        if not proc.out:
            return []

        return [line for line in proc.out.split('\n') if line]

    def set_neighbor(self, addr, ssid, nr):
        cmd = self.cmdline + ['set_neighbor', addr, 'ssid="%s"' % ssid, 'nr=%s' % nr]
        ctx.start_process(cmd).wait()

    def send_bss_transition(self, device, nr_list):
        # Send a BSS transition to a station (device). nr_list should be an
        # array of tuples containing the BSS address and neighbor report.
        # Parsing the neighbor report is a bit ugly but it makes it more
        # consistent with the set_neighbor() API, i.e. the same neighbor report
        # string could be used in both API's.
        pref = 1
        cmd = self.cmdline + ['bss_tm_req', device]
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

    @property
    def bssid(self):
        cmd = self.cmdline + ['status']
        proc = ctx.start_process(cmd)
        proc.wait()
        status = proc.out.split('\n')

        bssid = [x for x in status if x.startswith('bssid')]
        bssid = bssid[0].split('=')
        return bssid[1]

    @property
    def frequency(self):
        cmd = self.cmdline + ['status']
        proc = ctx.start_process(cmd)
        proc.wait()
        status = proc.out.split('\n')

        frequency = [x for x in status if x.startswith('freq')][0]
        frequency = frequency.split('=')[1]

        return int(frequency)
