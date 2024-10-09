#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
from iwd import IWD
from iwd import DeviceProvisioning
from wpas import Wpas
from hostapd import HostapdCLI
from hwsim import Hwsim
from config import ctx

class Test(unittest.TestCase):
    def test_iwd_as_enrollee(self):
        self.device.autoconnect = True
        self.hapd.reload()

        uri = self.device.dpp_start_enrollee()

        self.wpas.dpp_configurator_create(uri)
        self.wpas.dpp_configurator_start('ssidCCMP', 'secret123')

        condition = 'obj.state == DeviceState.connected'
        self.wd.wait_for_object_condition(self.device, condition)

    def test_iwd_as_enrollee_channel_switch(self):
        self.device.autoconnect = True
        self.hapd.reload()

        uri = self.device.dpp_start_enrollee()

        self.wpas.dpp_configurator_create(uri)
        self.wpas.dpp_configurator_start('ssidCCMP', 'secret123', freq=2462)

        condition = 'obj.state == DeviceState.connected'
        self.wd.wait_for_object_condition(self.device, condition)

    def test_iwd_as_enrollee_scan_after(self):
        self.wpas.disconnect()
        self.device.autoconnect = True
        uri = self.device.dpp_start_enrollee()

        self.wpas.dpp_configurator_create(uri)
        self.wpas.dpp_configurator_start('ssidCCMP', 'secret123')

        with self.assertRaises(Exception):
            self.device.get_ordered_network('ssidCCMP', scan_if_needed=False)

        self.hapd.reload()
        self.hapd.wait_for_event('AP-ENABLED')

        condition = 'obj.state == DeviceState.connected'
        self.wd.wait_for_object_condition(self.device, condition)

    def test_iwd_as_enrollee_no_ack(self):
        self.rule0.enabled = True
        self.device.autoconnect = True
        self.hapd.reload()

        uri = self.device.dpp_start_enrollee()

        self.wpas.dpp_configurator_create(uri)
        self.wpas.dpp_configurator_start('ssidCCMP', 'secret123')

        condition = 'obj.state == DeviceState.connected'
        self.wd.wait_for_object_condition(self.device, condition)

    def test_iwd_as_configurator(self):
        self.hapd.reload()
        self.hapd.wait_for_event('AP-ENABLED')

        IWD.copy_to_storage('ssidCCMP.psk')
        self.device.autoconnect = True

        condition = 'obj.state == DeviceState.connected'
        self.wd.wait_for_object_condition(self.device, condition)

        uri = self.device.dpp_start_configurator()

        self.wpas.dpp_enrollee_start(uri)

        self.wpas.wait_for_event('DPP-CONF-RECEIVED', timeout=30)

    def test_iwd_as_configurator_initiator(self):
        self.hapd.reload()
        self.hapd.wait_for_event('AP-ENABLED')

        IWD.copy_to_storage('ssidCCMP.psk')
        self.device.autoconnect = True

        condition = 'obj.state == DeviceState.connected'
        self.wd.wait_for_object_condition(self.device, condition)

        uri = self.wpas.dpp_enrollee_start(oper_and_channel='81/2')

        self.device.dpp_start_configurator(uri)

        self.wpas.wait_for_event('DPP-CONF-RECEIVED', timeout=30)

    def test_client_as_configurator(self):
        self.hapd.reload()
        self.hapd.wait_for_event('AP-ENABLED')

        IWD.copy_to_storage('ssidCCMP.psk')
        self.device.autoconnect = True

        condition = 'obj.state == DeviceState.connected'
        self.wd.wait_for_object_condition(self.device, condition)

        ctx.start_process(['iwctl', 'dpp', self.device.name, 'start-configurator'], check=True)

        dpp = DeviceProvisioning(self.device.device_path)

        self.wpas.dpp_enrollee_start(dpp.uri)

        self.wpas.wait_for_event('DPP-CONF-RECEIVED', timeout=30)

    def test_client_as_enrollee(self):
        self.device.autoconnect = True
        self.hapd.reload()

        ctx.start_process(['iwctl', 'dpp', self.device.name, 'start-enrollee'], check=True)

        dpp = DeviceProvisioning(self.device.device_path)

        self.wpas.dpp_configurator_create(dpp.uri)
        self.wpas.dpp_configurator_start('ssidCCMP', 'secret123')

        condition = 'obj.state == DeviceState.connected'
        self.wd.wait_for_object_condition(self.device, condition)

    def setUp(self):
        self.wpas = Wpas('wpas.conf')
        self.wd = IWD(True)
        self.device = self.wd.list_devices(1)[0]
        self.hapd = HostapdCLI('hostapd.conf')
        self.hapd.disable()
        self.hwsim = Hwsim()

        self.rule0 = self.hwsim.rules.create()
        self.rule0.prefix = 'd0'
        self.rule0.match_offset = 24
        self.rule0.match = '04 09 50 6f 9a 1a 01 01'
        self.rule0.match_times = 1
        self.rule0.drop = True

    def tearDown(self):
        # Tests end in various states, don't fail when tearing down.
        try:
            self.device.disconnect()
            self.device.dpp_stop()
        except:
            pass

        self.wpas.dpp_configurator_remove()
        self.wpas.clean_up()

        self.wd = None
        self.device = None
        self.wpas = None
        self.hapd = None
        self.rule0 = None
        IWD.clear_storage()

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        pass

if __name__ == '__main__':
    unittest.main(exit=True)
