#! /usr/bin/python3

import unittest
import sys, os

import iwd
from iwd import IWD
from iwd import PSKAgent
from iwd import NetworkType
from config import ctx
import testutil

class Test(unittest.TestCase):
    def test_connection_success(self):
        # Using main.conf containing APRanges. The APConfig SSID should override
        # this range.
        wd = IWD(True, '/tmp/dhcp')

        ns0 = ctx.get_namespace('ns0')

        wd_ns0 = IWD(True, '/tmp/dhcp', namespace=ns0)

        dev1 = wd_ns0.list_devices(1)[0]
        dev2, dev3, dev4, dev5 = wd.list_devices(4)
        dev3.disconnect()
        dev4.disconnect()
        dev5.disconnect()

        dev1.start_ap('APConfig')

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
            self.assertEqual(networks['APConfig'].type, NetworkType.psk)

            psk_agent = PSKAgent('password123')
            wd.register_psk_agent(psk_agent)

            try:
                dev2.disconnect()

                condition = 'not obj.connected'
                wd.wait_for_object_condition(dev2, condition)
            except:
                pass

            networks['APConfig'].network_object.connect()

            condition = 'obj.state == DeviceState.connected'
            wd.wait_for_object_condition(dev2, condition)

            testutil.test_iface_operstate(dev2.name)
            #
            # TODO: cannot yet check the AP interface IP since its in a
            #       different namespace.
            #
            testutil.test_ip_address_match(dev2.name, "192.168.1.3")

            testutil.test_ip_connected(('192.168.1.3', ctx), ('192.168.1.1', ns0))

            wd.unregister_psk_agent(psk_agent)

            dev2.disconnect()

            condition = 'not obj.connected'
            wd.wait_for_object_condition(networks['APConfig'].network_object,
                                         condition)

        finally:
            dev1.stop_ap()

    @classmethod
    def setUpClass(cls):
        IWD.copy_to_ap('dhcp/APConfig.ap')

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
