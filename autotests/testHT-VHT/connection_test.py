#! /usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import PSKAgent
from iwd import NetworkType
from hwsim import Hwsim
import testutil
from hostapd import HostapdCLI

class Test(unittest.TestCase):
    def do_connect(self, wd, device, hostapd):
        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        device.scan()

        condition = 'obj.scanning'
        wd.wait_for_object_condition(device, condition)

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        #
        # Scanning must be explicitly done to get updated RSSI values. Therefore
        # scan_if_needed is set false because of the previous scan.
        #
        ordered_network = device.get_ordered_network('testSSID', scan_if_needed=False)

        self.assertEqual(ordered_network.type, NetworkType.psk)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network.network_object.connect()

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        testutil.test_iface_operstate()
        testutil.test_ifaces_connected(device.name, hostapd.ifname)

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

    def test_connection_success(self):
        hwsim = Hwsim()
        non_ht_hostapd = HostapdCLI(config='non-ht-vht.conf')
        ht_hostapd = HostapdCLI(config='ht.conf')
        vht_hostapd = HostapdCLI(config='vht.conf')
        non_ht_radio = hwsim.get_radio('rad0')
        ht_radio = hwsim.get_radio('rad1')
        vht_radio = hwsim.get_radio('rad2')

        self.assertIsNotNone(non_ht_hostapd)
        self.assertIsNotNone(ht_hostapd)
        self.assertIsNotNone(vht_hostapd)

        rule0 = hwsim.rules.create()
        rule0.source = vht_radio.addresses[0]
        rule0.bidirectional = True
        rule0.signal = -5100
        rule0.enabled = True

        rule1 = hwsim.rules.create()
        rule1.source = ht_radio.addresses[0]
        rule1.bidirectional = True
        rule1.signal = -5200
        rule1.enabled = True

        rule2 = hwsim.rules.create()
        rule2.source = non_ht_radio.addresses[0]
        rule2.bidirectional = True
        rule2.signal = -5300
        rule2.enabled = True

        wd = IWD()

        psk_agent = PSKAgent("secret123")
        wd.register_psk_agent(psk_agent)

        device = wd.list_devices(1)[0]

        self.do_connect(wd, device, vht_hostapd)

        # lower VHT BSS signal, HT should now be preferred
        rule0.signal = -8200

        self.do_connect(wd, device, ht_hostapd)

        # lower HT BSS signal, basic rate BSS should now be preferred
        rule1.signal = -7600

        self.do_connect(wd, device, non_ht_hostapd)

        wd.unregister_psk_agent(psk_agent)

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
