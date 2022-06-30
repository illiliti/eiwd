#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
from iwd import IWD
from iwd import AdHocDevice
from config import ctx
import testutil

class Test(unittest.TestCase):

    def validate_connection(self, wd, client=False):
        dev1, dev2 = wd.list_devices(2)

        self.assertIsNotNone(dev1)
        self.assertIsNotNone(dev2)

        adhoc1 = dev1.start_adhoc("AdHocNetwork", "secret123")

        condition = 'obj.started == True'
        wd.wait_for_object_condition(adhoc1, condition)

        if not client:
            adhoc2 = dev2.start_adhoc("AdHocNetwork", "secret123")
        else:
            ctx.start_process(['iwctl', 'device', dev2.name, 'set-property',
                                'Mode', 'ad-hoc'], check=True)
            ctx.start_process(['iwctl', 'ad-hoc', dev2.name, 'start',
                                'AdHocNetwork', 'secret123'], check=True)
            adhoc2 = AdHocDevice(dev2.device_path)

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

    def test_client_adhoc(self):
        wd = IWD(True)
        self.validate_connection(wd, client=True)

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
