#!/usr/bin/python3

import unittest
import sys
import os

sys.path.append('../util')
from iwd import IWD
from iwd import IWD_CONFIG_DIR
from iwd import NetworkType
from hostapd import HostapdCLI
import testutil

class Test(unittest.TestCase):

    def test_connection_success(self):
        wd = self.wd

        hapd_hotspot = HostapdCLI(config='ssidHotspot.conf')
        hapd_wpa = HostapdCLI(config='ssidWPA2-1.conf')

        self.assertEqual(len(wd.list_known_networks()), 2)

        devices = wd.list_devices(1)
        device = devices[0]
        device.autoconnect = True

        condition = 'obj.scanning'
        wd.wait_for_object_condition(device, condition)

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        wpa_network = device.get_ordered_network("ssidWPA2-1")
        self.assertEqual(wpa_network.type, NetworkType.psk)

        #
        # First make sure we can connect to a provisioned, non-Hotspot network,
        # while there are hotspot networks in range. This should result in
        # autoconnect *after* ANQP is performed
        #
        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        testutil.test_iface_operstate()
        testutil.test_ifaces_connected(device.name, hapd_wpa.ifname)

        #
        # Remove provisioning file, this should cause a disconnect.
        #
        os.remove("/tmp/iwd/ssidWPA2-1.psk")

        condition = 'obj.state == DeviceState.disconnected'
        wd.wait_for_object_condition(device, condition)

        condition = 'len(obj.list_known_networks()) == 1'
        wd.wait_for_object_condition(wd, condition)

        condition = 'obj.scanning'
        wd.wait_for_object_condition(device, condition)

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        hotspot_network = device.get_ordered_network("Hotspot")
        self.assertEqual(hotspot_network.type, NetworkType.eap)

        #
        # Since there are no other provisioned networks, we should do ANQP and
        # autoconnect to the hotspot network.
        #
        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        testutil.test_iface_operstate()
        testutil.test_ifaces_connected(device.name, hapd_hotspot.ifname)

        os.remove('/tmp/iwd/hotspot/autoconnect.conf')

        #
        # make sure removal of hotspot conf file resulted in disconnect
        #
        condition = 'obj.state == DeviceState.disconnected'
        wd.wait_for_object_condition(device, condition)

        IWD.copy_to_storage('ssidWPA2-1.psk')

        condition = 'len(obj.list_known_networks()) == 1'
        wd.wait_for_object_condition(wd, condition)

        condition = 'obj.scanning'
        wd.wait_for_object_condition(device, condition)

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        hotspot_network = device.get_ordered_network("ssidWPA2-1")
        self.assertEqual(hotspot_network.type, NetworkType.psk)

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        testutil.test_iface_operstate()
        testutil.test_ifaces_connected(device.name, hapd_wpa.ifname)

        device.disconnect()

    @classmethod
    def setUpClass(cls):
        IWD.copy_to_hotspot('autoconnect.conf')
        IWD.copy_to_storage('ssidWPA2-1.psk')
        IWD.copy_to_storage('anqp_enabled.conf', storage_dir=IWD_CONFIG_DIR, name='main.conf')

        cls.wd = IWD(True)

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()
        os.remove('/tmp/main.conf')

        cls.wd = None

if __name__ == '__main__':
    unittest.main(exit=True)
