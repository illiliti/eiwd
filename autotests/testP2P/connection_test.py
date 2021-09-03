#!/usr/bin/python3

import unittest
import sys
import netifaces
import os
import time

import iwd
from iwd import IWD
import testutil
from config import ctx
from wpas import Wpas

class Test(unittest.TestCase):
    def test_1_client_go_neg_responder(self):
        self.p2p_connect_test(preauthorize=False, go=False)

    def test_2_client_go_neg_initiator(self):
        self.p2p_connect_test(preauthorize=True, go=False)

    def test_3_go_go_neg_responder(self):
        self.p2p_connect_test(preauthorize=False, go=True)

    def test_4_go_go_neg_initiator(self):
        self.p2p_connect_test(preauthorize=True, go=True)

    def p2p_connect_test(self, preauthorize, go):
        wd = IWD()
        wpas = self.wpas = Wpas(p2p=True)
        wpas_go_intent = 10 if not go else 1

        # Not strictly necessary but prevents the station interface from queuing its scans
        # in the wiphy radio work queue and delaying P2P scans.
        wd.list_devices(1)[0].disconnect()

        devices = wd.list_p2p_devices(1)
        p2p = self.p2p = devices[0]
        p2p.enabled = True
        p2p.name = 'testdev1'

        wpas.p2p_find()
        p2p.discovery_request = True
        wd.wait(5)
        wd.wait_for_object_condition(wpas, 'len(obj.p2p_peers) == 1', max_wait=20)
        p2p.discovery_request = False
        wpas.p2p_listen()

        peers = p2p.get_peers()
        self.assertEqual(len(peers), 1)
        peer = next(iter(peers.values()))
        self.assertEqual(peer.name, wpas.config['device_name'])
        self.assertEqual(peer.category, 'display')
        self.assertEqual(peer.subcategory, 'monitor')

        wpas_peer = next(iter(wpas.p2p_peers.values()))
        self.assertEqual(wpas_peer['name'], p2p.name)
        self.assertEqual(wpas_peer['pri_dev_type'], '1-0050F204-6') # 1 == Computer, 6 == Desktop
        self.assertEqual(wpas_peer['config_methods'], '0x1080')

        if preauthorize:
            wpas.p2p_authorize(wpas_peer, go_intent=wpas_go_intent)

        peer.connect(wait=False)

        self.assertEqual(len(wpas.p2p_go_neg_requests), 0)
        self.assertEqual(len(wpas.p2p_clients), 0)
        wd.wait_for_object_condition(wpas, 'len(obj.p2p_go_neg_requests) == 1', max_wait=3)
        request = wpas.p2p_go_neg_requests[wpas_peer['p2p_dev_addr']]

        if not preauthorize:
            self.assertEqual(request['dev_passwd_id'], '4')
            self.assertEqual(request['go_intent'], '2') # Hardcoded in src/p2p.c

            wpas.p2p_accept_go_neg_request(request, go_intent=wpas_go_intent)

        wd.wait_for_object_condition(request, '\'success\' in obj', max_wait=3)
        self.assertEqual(request['success'], True)
        self.assertEqual(request['role'], 'GO' if not go else 'client')
        self.assertEqual(request['wps_method'], 'PBC')
        self.assertEqual(request['p2p_dev_addr'], wpas_peer['p2p_dev_addr'])

        if go:
            # For some reason wpa_supplicant's newly created P2P-client interface doesn't inherit
            # the settings from the main interface which were loaded from the config file
            # (P2P-device and P2P-GO interfaces do), we need to set config_methods again.
            peer_ifname = 'p2p-' + wpas.interface.name + '-0'
            wpas.set('config_methods', wpas.config['config_methods'], ifname=peer_ifname)
            wpas.set('device_name', wpas.config['device_name'], ifname=peer_ifname)
            wpas.set('device_type', wpas.config['device_type'], ifname=peer_ifname)

        wd.wait_for_object_condition(wpas, 'obj.p2p_group is not None', max_wait=3)
        peer_ifname = wpas.p2p_group['ifname']
        self.assertEqual(wpas.p2p_group['role'], 'GO' if not go else 'client')

        if not go:
            ctx.start_process(['ifconfig', peer_ifname, '192.168.1.20', 'netmask', '255.255.255.0']).wait()
            os.system('> /tmp/dhcp.leases')
            dhcp = ctx.start_process(['dhcpd', '-f', '-cf', '/tmp/dhcpd.conf', '-lf', '/tmp/dhcp.leases', peer_ifname])
            self.dhcp = dhcp

            wd.wait_for_object_condition(wpas, 'len(obj.p2p_clients) == 1', max_wait=3)
            client = wpas.p2p_clients[request['peer_iface']]
            self.assertEqual(client['p2p_dev_addr'], wpas_peer['p2p_dev_addr'])
        else:
            self.assertEqual(wpas.p2p_group['ip_addr'], '192.168.1.2')
            self.assertEqual(wpas.p2p_group['ip_mask'], '255.255.255.240')
            self.assertEqual(wpas.p2p_group['go_ip_addr'], '192.168.1.1')
            dhcp = ctx.start_process(['dhclient', '-v', '-d', '--no-pid', '-cf', '/dev/null', '-lf', '/tmp/dhcp.leases',
                '-sf', '/tmp/dhclient-script', peer_ifname])
            self.dhcp = dhcp

        wd.wait_for_object_condition(peer, 'obj.connected', max_wait=15)
        time.sleep(1) # Give the client time to set the IP
        our_ip = netifaces.ifaddresses(peer.connected_interface)[netifaces.AF_INET][0]['addr']
        peer_ip = netifaces.ifaddresses(peer_ifname)[netifaces.AF_INET][0]['addr']
        self.assertEqual(peer.connected_ip, peer_ip)

        if not go:
            self.assertEqual(our_ip, '192.168.1.30')
            self.assertEqual(peer_ip, '192.168.1.20')
        else:
            self.assertEqual(our_ip, '192.168.1.1')
            self.assertEqual(peer_ip, '192.168.1.2')

        testutil.test_iface_operstate(peer.connected_interface)
        testutil.test_ifaces_connected(peer.connected_interface, peer_ifname)

        peer.disconnect()
        if not go:
            wd.wait_for_object_condition(wpas, 'len(obj.p2p_clients) == 0', max_wait=3)
        else:
            wd.wait_for_object_condition(wpas, 'obj.p2p_group is None', max_wait=15)
        self.assertEqual(peer.connected, False)

    def setUp(self):
        self.p2p = None
        self.wpas = None
        self.dhcp = None

    def tearDown(self):
        if self.p2p is not None:
            try:
                self.p2p.enabled = False
            except:
                pass
        if self.wpas is not None:
            self.wpas.clean_up()
            self.wpas = None
        if self.dhcp is not None:
            ctx.stop_process(self.dhcp)
        for path in ['/tmp/dhcp.leases']:
            if os.path.exists(path):
                os.remove(path)

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
