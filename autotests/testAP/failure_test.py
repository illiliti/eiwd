#! /usr/bin/python3

import unittest
import sys, os

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import PSKAgent
from iwd import NetworkType
from hostapd import HostapdCLI
import testutil

class Test(unittest.TestCase):

    def client_connect(self, wd, dev):
        hostapd = HostapdCLI(config='psk-ccmp.conf')

        ordered_network = dev.get_ordered_network('TestAP1', True)

        self.assertEqual(ordered_network.type, NetworkType.psk)

        psk_agent = PSKAgent('Password1')
        wd.register_psk_agent(psk_agent)

        ordered_network.network_object.connect()

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(dev, condition)

        wd.unregister_psk_agent(psk_agent)

        testutil.test_iface_operstate(dev.name)
        testutil.test_ifaces_connected(hostapd.ifname, dev.name)

        dev.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

    def test_connection_failure(self):
        wd = IWD(True)

        dev1, dev2 = wd.list_devices(2)

        self.client_connect(wd, dev1)

        dev1.start_ap('TestAP2', 'Password2')

        try:
            condition = 'not obj.scanning'
            wd.wait_for_object_condition(dev2, condition)
            dev2.scan()
            condition = 'obj.scanning'
            wd.wait_for_object_condition(dev2, condition)
            condition = 'not obj.scanning'
            wd.wait_for_object_condition(dev2, condition)

            networks = {}
            networks['TestAP1'] = dev2.get_ordered_network('TestAP1')
            networks['TestAP2'] = dev2.get_ordered_network('TestAP2', full_scan=True)

            self.assertEqual(networks['TestAP1'].type, NetworkType.psk)
            self.assertEqual(networks['TestAP2'].type, NetworkType.psk)

            psk_agent = PSKAgent('InvalidPassword')
            wd.register_psk_agent(psk_agent)

            with self.assertRaises(iwd.FailedEx):
                networks['TestAP2'].network_object.connect()

            wd.unregister_psk_agent(psk_agent)
        finally:
            dev1.stop_ap()

        # Finally test dev1 can go to client mode and connect again
        self.client_connect(wd, dev1)

    @classmethod
    def setUpClass(cls):
        IWD.copy_to_storage('TestAP1.psk')

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
