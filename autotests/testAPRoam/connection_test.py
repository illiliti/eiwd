#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import PSKAgent
from iwd import NetworkType

from hostapd import HostapdCLI
from hwsim import Hwsim

class Test(unittest.TestCase):

    def test_connection_success(self):
        hwsim = Hwsim()

        bss_hostapd = [ HostapdCLI(config='ssid1.conf'),
                        HostapdCLI(config='ssid2.conf'),
                        HostapdCLI(config='ssid3.conf') ]
        bss_radio =  [ hwsim.get_radio('rad0'),
                       hwsim.get_radio('rad1'),
                       hwsim.get_radio('rad2') ]

        rule0 = hwsim.rules.create()
        rule0.source = bss_radio[0].addresses[0]
        rule0.bidirectional = True

        rule1 = hwsim.rules.create()
        rule1.source = bss_radio[1].addresses[0]
        rule1.bidirectional = True

        rule2 = hwsim.rules.create()
        rule2.source = bss_radio[2].addresses[0]
        rule2.bidirectional = True

        rule0.signal = -6000
        rule1.signal = -6900
        rule2.signal = -8000

        wd = IWD()

        psk_agent = PSKAgent("secret123")
        wd.register_psk_agent(psk_agent)

        devices = wd.list_devices(1)
        device = devices[0]

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        device.scan()

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        ordered_network = device.get_ordered_network('TestAPRoam')

        self.assertEqual(ordered_network.type, NetworkType.psk)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network.network_object.connect()

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        bss_hostapd[0].wait_for_event('AP-STA-CONNECTED')

        self.assertTrue(bss_hostapd[0].list_sta())
        self.assertFalse(bss_hostapd[1].list_sta())

        bss_hostapd[0].send_bss_transition(device.address,
                [(bss_radio[1].addresses[0], '8f0000005102060603000000'),
                 (bss_radio[2].addresses[0], '8f0000005103060603000000')])

        condition = 'obj.state == DeviceState.roaming'
        wd.wait_for_object_condition(device, condition)

        condition = 'obj.state != DeviceState.roaming'
        wd.wait_for_object_condition(device, condition)

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        self.assertEqual(device.state, iwd.DeviceState.connected)
        self.assertTrue(bss_hostapd[1].list_sta())
        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        wd.unregister_psk_agent(psk_agent)

        rule0.remove()
        rule1.remove()
        rule2.remove()

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
