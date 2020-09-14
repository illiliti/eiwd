#!/usr/bin/python3

import unittest
import sys
import time

sys.path.append('../util')
import iwd
from iwd import IWD
import testutil

class Test(unittest.TestCase):

    def validate_connection(self, wd):
        dev1, dev2 = wd.list_devices(2)

        self.assertIsNotNone(dev1)
        self.assertIsNotNone(dev2)

        adhoc1 = dev1.start_adhoc("AdHocNetwork", "secret123")

        condition = 'obj.started == True'
        wd.wait_for_object_condition(adhoc1, condition)

        adhoc2 = dev2.start_adhoc("AdHocNetwork", "secret123")

        condition = 'obj.started == True'
        wd.wait_for_object_condition(adhoc1, condition)

        condition = '"%s" in obj.connected_peers' % dev2.address
        wd.wait_for_object_condition(adhoc1, condition)

        condition = '"%s" in obj.connected_peers' % dev1.address
        wd.wait_for_object_condition(adhoc2, condition)

        testutil.test_iface_operstate(dev1.name)
        testutil.test_iface_operstate(dev2.name)
        testutil.test_ifaces_connected(dev1.name, dev2.name)

    def test_connection_success(self):
        wd = IWD(True)

        self.validate_connection(wd)

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
