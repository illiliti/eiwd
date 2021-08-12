#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import PSKAgent
from iwd import NetworkType

class TestMFP(unittest.TestCase):
    '''
    The bellow test cases excesise the following MFP option setting scenarios:

    IWD_MFP: AP_MFP:  Result:
    0        0        No MFP, connection succeeds
    0        1        No MFP, connection succeeds
    0        2        Not capable error
    1        0        No MFP, connection succeeds
    1        1        MFP enabled, connection succeeds
    1        2        MFP enabled, connection succeeds
    2        0        Not capable error
    2        1        MFP enabled, connection succeeds
    2        2        MFP enabled, connection succeeds

    where:
        0 - MFP is disabled
        1 - MFP is optional
        2 - MFP is required
    '''

    def check_mfp_connection(self, wd, device, ssid, throws_exception):
        ordered_network = device.get_ordered_network(ssid)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        if throws_exception:
            with self.assertRaises(iwd.NotSupportedEx):
                ordered_network.network_object.connect()
            return
        else:
            ordered_network.network_object.connect()

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        IWD.clear_storage()

    def stage_iwd(self, wd, config_dir):
        psk_agent = PSKAgent( ['secret123', 'secret123', 'secret123'] )
        wd.register_psk_agent(psk_agent)

        devices = wd.list_devices(1)
        self.assertIsNotNone(devices)
        device = devices[0]

        if config_dir == '/tmp/IWD-MFP2':
            self.check_mfp_connection(wd, device, 'ssidMFP0', True)
        else:
            self.check_mfp_connection(wd, device, 'ssidMFP0', False)

        self.check_mfp_connection(wd, device, 'ssidMFP1', False)

        if config_dir == '/tmp/IWD-MFP0':
            self.check_mfp_connection(wd, device, 'ssidMFP2', True)
        else:
            self.check_mfp_connection(wd, device, 'ssidMFP2', False)

        wd.unregister_psk_agent(psk_agent)

    def test_iwd_mfp0(self):
        wd = IWD(True, '/tmp/IWD-MFP0')

        self.stage_iwd(wd, '/tmp/IWD-MFP0')

    def test_iwd_mfp1(self):
        wd = IWD(True, '/tmp/IWD-MFP1')

        self.stage_iwd(wd, '/tmp/IWD-MFP1')

    def test_iwd_mfp2(self):
        wd = IWD(True, '/tmp/IWD-MFP2')

        self.stage_iwd(wd, '/tmp/IWD-MFP2')

if __name__ == '__main__':
    unittest.main(exit=True)
