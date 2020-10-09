#!/usr/bin/python3

import unittest
import sys
import netifaces
import os

import iwd
from iwd import IWD
import testutil
from config import ctx
from wpas import Wpas

class Test(unittest.TestCase):
    def test_1_client_go_neg_responder(self):
        self.p2p_client_test(False)

    def test_2_client_go_neg_initiator(self):
        self.p2p_client_test(True)

    def p2p_client_test(self, preauthorize):
        wpas = Wpas(p2p=True)
        wd = IWD()

        # Not strictly necessary but prevents the station interface from queuing its scans
        # in the wiphy radio work queue and delaying P2P scans.
        wd.list_devices(1)[0].disconnect()

        devices = wd.list_p2p_devices(1)
        p2p = devices[0]
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
            wpas.p2p_authorize(wpas_peer)

        peer.connect(wait=False)

        self.assertEqual(len(wpas.p2p_go_neg_requests), 0)
        self.assertEqual(len(wpas.p2p_clients), 0)
        wd.wait_for_object_condition(wpas, 'len(obj.p2p_go_neg_requests) == 1', max_wait=3)
        request = wpas.p2p_go_neg_requests[wpas_peer['p2p_dev_addr']]

        if not preauthorize:
            self.assertEqual(request['dev_passwd_id'], '4')
            self.assertEqual(request['go_intent'], '2') # Hardcoded in src/p2p.c

            wpas.p2p_accept_go_neg_request(request)

        wd.wait_for_object_condition(request, '\'success\' in obj', max_wait=3)
        self.assertEqual(request['success'], True)
        self.assertEqual(request['role'], 'GO')
        self.assertEqual(request['wps_method'], 'PBC')
        self.assertEqual(request['p2p_dev_addr'], wpas_peer['p2p_dev_addr'])

        wd.wait_for_object_condition(wpas, 'obj.p2p_group is not None', max_wait=3)
        go_ifname = wpas.p2p_group['ifname']
        ctx.start_process(['ifconfig', go_ifname, '192.168.1.20', 'netmask', '255.255.255.0'], wait=True)
        os.system('> /tmp/dhcpd.leases')
        dhcpd = ctx.start_process(['dhcpd', '-f', '-cf', '/tmp/dhcpd.conf', '-lf', '/tmp/dhcpd.leases', go_ifname])

        wd.wait_for_object_condition(wpas, 'len(obj.p2p_clients) == 1', max_wait=3)
        client = wpas.p2p_clients[request['peer_iface']]
        self.assertEqual(client['p2p_dev_addr'], wpas_peer['p2p_dev_addr'])

        wd.wait_for_object_condition(peer, 'obj.connected', max_wait=15)
        our_ip = netifaces.ifaddresses(peer.connected_interface)[netifaces.AF_INET][0]['addr']
        self.assertEqual(peer.connected_ip, '192.168.1.20')
        self.assertEqual(our_ip, '192.168.1.30')

        testutil.test_iface_operstate(peer.connected_interface)
        testutil.test_ifaces_connected(peer.connected_interface, go_ifname)

        peer.disconnect()
        wd.wait_for_object_condition(wpas, 'len(obj.p2p_clients) == 0', max_wait=3)
        self.assertEqual(peer.connected, False)

        p2p.enabled = False
        ctx.stop_process(dhcpd)
        wpas.clean_up()

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
