#! /usr/bin/python3

import unittest
import sys, os

import iwd
from iwd import IWD
from iwd import PSKAgent
from iwd import NetworkType
from config import ctx
import testutil

from validation import validate

class Test(unittest.TestCase):
    def test_connection_success(self):
        wd = IWD(True, '/tmp/dhcp')

        # dev1, dev3, and dev4 are all AP's
        # The configured IP range only supports 2 subnets, so dev4 should fail
        # to start AP.
        dev1, dev2, dev3, dev4 = wd.list_devices(4)

        dev1.start_ap('TestAP2', "Password2")
        dev3.start_ap('TestAP3', 'Password3')

        with self.assertRaises(iwd.AlreadyExistsEx):
            dev4.start_ap('TestAP4', 'Password4')

        validate(wd, dev2, dev1, 'TestAP2', 'Password2', ip_checks=False)

        network = dev2.get_ordered_network('TestAP2', full_scan=True)

        try:
            testutil.test_ip_address_match(dev1.name, "192.168.80.1")
            testutil.test_ip_address_match(dev2.name, "192.168.80.2")
            ip = "192.168.80.1"
        except:
            testutil.test_ip_address_match(dev1.name, "192.168.80.17")
            testutil.test_ip_address_match(dev2.name, "192.168.80.18")
            ip = "192.168.80.17"

        dev2.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(network.network_object, condition)

        # This should release the IP */
        dev1.stop_ap()

        # This should now succeed and the IP should match the old IP dev1
        # got initially.
        dev4.start_ap('TestAP4', 'Password4')

        testutil.test_ip_address_match(dev4.name, ip)

        dev1.stop_ap()
        dev3.stop_ap()
        dev4.stop_ap()

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
