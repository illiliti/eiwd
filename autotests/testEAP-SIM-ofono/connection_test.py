#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import NetworkType
from hlrauc import AuthCenter
from ofono import Ofono
from config import ctx

class Test(unittest.TestCase):

    def test_connection_success(self):
        ofono = Ofono()
        ofono.enable_modem('/phonesim')
        ofono.wait_for_sim_auth()

        wd = IWD()

        devices = wd.list_devices(1)
        device = devices[0]

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        device.scan()

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        ordered_network = device.get_ordered_network('ssidEAP-SIM')

        self.assertEqual(ordered_network.type, NetworkType.eap)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network.network_object.connect()

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

    @classmethod
    def setUpClass(cls):
        if not ctx.is_process_running('ofonod'):
            cls.skipTest(cls, "ofono not running")

        IWD.copy_to_storage('ssidEAP-SIM.8021x')

        cls.auth = AuthCenter('/tmp/hlrauc.sock', '/tmp/sim.db')

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

        cls.auth.stop()

if __name__ == '__main__':
    unittest.main(exit=True)
