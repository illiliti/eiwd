#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
from iwd import IWD, SharedCodeAgent, DeviceState
from iwd import DeviceProvisioning
from wpas import Wpas
from hostapd import HostapdCLI
from hwsim import Hwsim
from config import ctx
from time import time
import os

class Test(unittest.TestCase):
    def auto_connect(self):
        IWD.copy_to_storage('ssidCCMP.psk')
        self.device.autoconnect = True

        condition = 'obj.state == DeviceState.connected'
        self.wd.wait_for_object_condition(self.device, condition)

    def test_configurator_stops_on_disconnect(self):
        self.auto_connect()

        self.device.dpp_start_configurator()

        self.device.disconnect()

        condition = 'obj.state == DeviceState.disconnected'
        self.wd.wait_for_object_condition(self.device, condition)

        self.assertEqual(self.device._device_provisioning.started, False)

    def test_enrollee_stops_on_connect(self):
        # Scan to get a list of networks
        self.device.scan()
        self.wd.wait_for_object_condition(self.device, 'obj.scanning == True')
        self.wd.wait_for_object_condition(self.device, 'obj.scanning == False')

        self.device.dpp_start_enrollee()

        network = self.device.get_ordered_network("ssidCCMP")
        network.network_object.connect()

        condition = 'obj.state == DeviceState.connected'
        self.wd.wait_for_object_condition(self.device, condition)

        self.assertEqual(self.device._device_provisioning.started, False)

    def test_enrollee_disconnects_automatically(self):
        self.auto_connect()

        self.device.dpp_start_enrollee()

        condition = 'obj.state == DeviceState.disconnected'
        self.wd.wait_for_object_condition(self.device, condition)

    def test_enrollee_autoconnect_stays_on(self):
        # Put in an autoconnecting state, no saved profile though
        self.device.autoconnect = True

        self.device.dpp_start_enrollee()

        # DPP should set autoconnect false, but then re-enable after it stops
        self.wd.wait_for_object_condition(self.device, "obj.autoconnect == False")
        self.wd.wait_for_object_condition(self.device._device_provisioning, "obj.started == True")

        # Stop DPP
        self.device.dpp_stop()
        self.wd.wait_for_object_condition(self.device, "obj.autoconnect == True")

    def test_enrollee_autoconnect_stays_off(self):
        # Autoconnect should be off by default

        self.device.dpp_start_enrollee()

        # DPP should set autoconnect false, but stay off after it stops
        self.wd.wait_for_object_condition(self.device, "obj.autoconnect == False")
        self.wd.wait_for_object_condition(self.device._device_provisioning, "obj.started == True")

        # Stop DPP
        self.device.dpp_stop()
        self.wd.wait_for_object_condition(self.device, "obj.autoconnect == False")

    def setUp(self):
        self.wd = IWD(True)
        self.device = self.wd.list_devices(1)[0]

    def tearDown(self):
        self.wd.stop()
        self.wd = None

    @classmethod
    def setUpClass(cls):
        hapd = HostapdCLI(config="hostapd.conf")
        hapd.reload()

        hapd.wait_for_event("AP-ENABLED")

    @classmethod
    def tearDownClass(cls):
        pass

if __name__ == '__main__':
    unittest.main(exit=True)