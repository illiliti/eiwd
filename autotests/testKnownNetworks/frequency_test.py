#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
from iwd import IWD
from iwd import PSKAgent
from hwsim import Hwsim
import os
from configparser import ConfigParser

class Test(unittest.TestCase):
    def connect_network(self, wd, device, network):
        ordered_network = device.get_ordered_network(network, full_scan=True)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network.network_object.connect()

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

    def test_connection_success(self):
        wd = self.wd

        psk_agent = PSKAgent("secret123")
        wd.register_psk_agent(psk_agent)

        devices = wd.list_devices(1)
        device = devices[0]


        # Set the signals so that the 2.4GHz ranking will be higher
        self.ssidccmp_2g_rule.signal = -2000
        self.ssidccmp_5g_rule.signal = -8000

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

        # The 2.4GHz frequency should come first, as it was ranked higher
        self.assertEqual('2412', psk_freqs[0])
        self.assertEqual('5180', psk_freqs[1])

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

        # Now set the signals so that the 5GHz ranking will be higher
        self.ssidccmp_2g_rule.signal = -8000
        self.ssidccmp_5g_rule.signal = -2000

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
        # Now the 5GHz frequency should be first
        self.assertEqual('5180', psk_freqs[0])
        self.assertEqual('2412', psk_freqs[1])

    def test_maximum_frequencies(self):
        psk_agent = PSKAgent("secret123")
        self.wd.register_psk_agent(psk_agent)

        devices = self.wd.list_devices(1)
        device = devices[0]

        # Connect and generate a known frequencies file
        self.connect_network(self.wd, device, 'ssidCCMP')

        self.wd.unregister_psk_agent(psk_agent)

        #
        # Rewrite the known frequencies file to move the valid network
        # frequencies to the end, past the maximum for a quick scan
        #
        config = ConfigParser()
        config.read('/tmp/iwd/.known_network.freq')
        for s in config.sections():
            if os.path.basename(config[s]['name']) == 'ssidCCMP.psk':
                config.set(s, 'list', "2417 2422 2427 2432 2437 2442 2447 2452 2457 2462 2467 2472 2484 2412 5180")
                break

        self.wd.stop()

        with open('/tmp/iwd/.known_network.freq', 'w') as f:
            config.write(f)

        self.wd = IWD(True)

        devices = self.wd.list_devices(1)
        device = devices[0]

        device.autoconnect = True

        device.wait_for_event("autoconnect_quick")

        condition = "obj.scanning == True"
        self.wd.wait_for_object_condition(device, condition)

        condition = "obj.scanning == False"
        self.wd.wait_for_object_condition(device, condition)

        #
        # Check that the quick scan didn't return any results
        #
        with self.assertRaises(Exception):
            device.get_ordered_network("ssidCCMP", scan_if_needed=False)

        device.wait_for_event("autoconnect_full")

        condition = "obj.scanning == True"
        self.wd.wait_for_object_condition(device, condition)

        condition = "obj.scanning == False"
        self.wd.wait_for_object_condition(device, condition)

        #
        # The full scan should now see the network
        #
        device.get_ordered_network("ssidCCMP", scan_if_needed=False)

    def setUp(self):
        self.wd = IWD(True)

    def tearDown(self):
        self.wd.stop()
        self.wd = None

    @classmethod
    def setUpClass(cls):
        IWD.copy_to_hotspot('example.conf')
        conf = '[General]\nDisableANQP=0\n'
        os.system('echo "%s" > /tmp/main.conf' % conf)

        hwsim = Hwsim()

        cls.ssidccmp_2g_rule = hwsim.rules.create()
        cls.ssidccmp_2g_rule.source = hwsim.get_radio('rad1').addresses[0]
        cls.ssidccmp_2g_rule.enabled = True

        cls.ssidccmp_5g_rule = hwsim.rules.create()
        cls.ssidccmp_5g_rule.source = hwsim.get_radio('rad2').addresses[0]
        cls.ssidccmp_5g_rule.enabled = True

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()
        os.remove('/tmp/main.conf')

        cls.ssidccmp_2g_rule.remove()
        cls.ssidccmp_5g_rule.remove()

if __name__ == '__main__':
    unittest.main(exit=True)
