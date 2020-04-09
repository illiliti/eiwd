#!/usr/bin/python3

import unittest
import sys
import time
from time import sleep

sys.path.append('../util')
import iwd
from iwd import IWD
import testutil

class Test(unittest.TestCase):

    def validate_connection(self, wd):
        dev1, dev2 = wd.list_devices(2)

        self.assertIsNotNone(dev1)
        self.assertIsNotNone(dev2)

        dev1.start_adhoc("AdHocNetwork")
        sleep(1)
        dev2.start_adhoc("AdHocNetwork")

        dev1.adhoc_wait_for_connected(dev2.address)
        dev2.adhoc_wait_for_connected(dev1.address)

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
