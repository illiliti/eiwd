#!/usr/bin/python3

import unittest
import sys
import time

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import NetworkType
from hlrauc import AuthCenter
from ofono import Ofono

class Test(unittest.TestCase):
    def validate_connection(self, wd):
        devices = wd.list_devices(1)
        self.assertIsNotNone(devices)
        device = devices[0]

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        device.scan()

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        ordered_network = device.get_ordered_network('ssidEAP-PEAP-SIM')

        self.assertEqual(ordered_network.type, NetworkType.eap)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network.network_object.connect()

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)


    def test_connection_success(self):
        ofono = Ofono()
        ofono.enable_modem('/phonesim')
        ofono.wait_for_sim_auth()

        wd = IWD(True)

        self.validate_connection(wd)

    @classmethod
    def setUpClass(cls):
        cls.auth = AuthCenter('/tmp/hlrauc.sock', '/tmp/sim.db')

        IWD.copy_to_storage('ssidEAP-PEAP-SIM.8021x')

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

        cls.auth.stop()
        cls.auth = None

if __name__ == '__main__':
    unittest.main(exit=True)
