#! /usr/bin/python3

import unittest
import sys, os

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import PSKAgent
from iwd import NetworkType
import hostapd
import testutil

class Test(unittest.TestCase):

    def client_connect(self, wd, dev):
        condition = 'not obj.scanning'
        wd.wait_for_object_condition(dev, condition)

        if not dev.get_ordered_networks():
            dev.scan()
            condition = 'obj.scanning'
            wd.wait_for_object_condition(dev, condition)
            condition = 'not obj.scanning'
            wd.wait_for_object_condition(dev, condition)

        ordered_network = dev.get_ordered_network('TestAP1')

        self.assertEqual(ordered_network.type, NetworkType.psk)

        psk_agent = PSKAgent('Password1')
        wd.register_psk_agent(psk_agent)

        ordered_network.network_object.connect()

        condition = 'obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        wd.unregister_psk_agent(psk_agent)

        testutil.test_iface_operstate(dev.name)
        testutil.test_ifaces_connected(list(hostapd.hostapd_map.keys())[0],
                                       dev.name)

        dev.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

    def test_connection_success(self):
        wd = IWD()

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

            ordered_networks = dev2.get_ordered_networks()
            networks = { n.name: n for n in ordered_networks }
            self.assertEqual(networks['TestAP1'].type, NetworkType.psk)
            self.assertEqual(networks['TestAP2'].type, NetworkType.psk)

            psk_agent = PSKAgent('Password2')
            wd.register_psk_agent(psk_agent)

            try:
                dev2.disconnect()
                condition = 'not obj.connected'
                wd.wait_for_object_condition(dev2, condition)
            except:
                pass

            networks['TestAP2'].network_object.connect()

            condition = 'obj.connected'
            wd.wait_for_object_condition(networks['TestAP2'].network_object,
                                         condition)

            testutil.test_iface_operstate(dev2.name)
            testutil.test_ifaces_connected(dev1.name, dev2.name)

            wd.unregister_psk_agent(psk_agent)

            dev2.disconnect()

            condition = 'not obj.connected'
            wd.wait_for_object_condition(networks['TestAP2'].network_object,
                                         condition)
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
