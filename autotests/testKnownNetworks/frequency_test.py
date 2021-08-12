#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import PSKAgent
from iwd import NetworkType
import testutil
import os
from configparser import ConfigParser

class Test(unittest.TestCase):
    def connect_network(self, wd, device, network):
        ordered_network = device.get_ordered_network(network)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network.network_object.connect()

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

    def test_connection_success(self):
        wd = IWD(True, '/tmp')

        psk_agent = PSKAgent("secret123")
        wd.register_psk_agent(psk_agent)

        devices = wd.list_devices(1)
        device = devices[0]

        #
        # Connect to the PSK network, then Hotspot so IWD creates 2 entries in
        # the known frequency file.
        #

        self.connect_network(wd, device, 'ssidCCMP')

        wd.unregister_psk_agent(psk_agent)

        psk_agent = PSKAgent('abc', ('domain\\user', 'testpasswd'))
        wd.register_psk_agent(psk_agent)

        self.connect_network(wd, device, 'Hotspot')

        wd.unregister_psk_agent(psk_agent)

        psk_freqs = None
        psk_uuid = None
        hs20_freqs = None
        hs20_uuid = None
        config = ConfigParser()
        config.read('/tmp/iwd/.known_network.freq')
        for s in config.sections():
            if os.path.basename(config[s]['name']) == 'ssidCCMP.psk':
                psk_freqs = config[s]['list']
                psk_freqs = psk_freqs.split(' ')
                psk_uuid = s
            elif os.path.basename(config[s]['name']) == 'example.conf':
                hs20_freqs = config[s]['list']
                hs20_freqs = hs20_freqs.split(' ')
                hs20_uuid = s

        #
        # Verify the frequencies are what we expect
        #
        self.assertIsNotNone(psk_freqs)
        self.assertIsNotNone(psk_uuid)
        self.assertIn('5180', psk_freqs)
        self.assertIn('2412', psk_freqs)

        self.assertIsNotNone(hs20_freqs)
        self.assertIsNotNone(hs20_uuid)
        self.assertIn('2412', hs20_freqs)

        #
        # Forget all know networks, this should remove all entries in the
        # known frequencies file.
        #
        for n in wd.list_known_networks():
            n.forget()

        psk_agent = PSKAgent("secret123")
        wd.register_psk_agent(psk_agent)

        #
        # Reconnect, this should generate a completely new UUID since we
        # previously forgot the network.
        #
        self.connect_network(wd, device, 'ssidCCMP')

        wd.unregister_psk_agent(psk_agent)

        #
        # Ensure that a new UUID was created and that we still have the same
        # frequencies listed.
        #
        psk_freqs = None
        psk_uuid2 = None
        hs20_freqs = None
        config = ConfigParser()
        config.read('/tmp/iwd/.known_network.freq')
        for s in config.sections():
            self.assertNotEqual(os.path.basename(config[s]['name']),
                                    'example.conf')
            if os.path.basename(config[s]['name']) == 'ssidCCMP.psk':
                psk_freqs = config[s]['list']
                psk_freqs = psk_freqs.split(' ')
                psk_uuid2 = s

        self.assertIsNotNone(psk_freqs)
        self.assertIsNotNone(psk_uuid2)
        self.assertNotEqual(psk_uuid, psk_uuid2)
        self.assertIn('5180', psk_freqs)
        self.assertIn('2412', psk_freqs)

    @classmethod
    def setUpClass(cls):
        IWD.copy_to_hotspot('example.conf')
        conf = '[General]\nDisableANQP=0\n'
        os.system('echo "%s" > /tmp/main.conf' % conf)

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()
        os.remove('/tmp/main.conf')

if __name__ == '__main__':
    unittest.main(exit=True)
