#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import PSKAgent
from iwd import NetworkType
from iwd import IWD_CONFIG_DIR

from hostapd import HostapdCLI
from hwsim import Hwsim

import time

class Test(unittest.TestCase):
    def test_temp_blacklist(self):
        rule0 = self.rule0
        rule1 = self.rule1
        rule2 = self.rule2

        bss_hostapd = self.bss_hostapd
        wd = self.wd

        rule0.signal = -8000
        rule1.signal = -7000
        rule2.signal = -2000

        psk_agent = PSKAgent("secret123")
        wd.register_psk_agent(psk_agent)

        dev1, dev2 = wd.list_devices(2)

        ordered_network = dev1.get_ordered_network("TestBlacklist", full_scan=True)

        self.assertEqual(ordered_network.type, NetworkType.psk)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network.network_object.connect()

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(dev1, condition)

        bss_hostapd[2].wait_for_event('AP-STA-CONNECTED %s' % dev1.address)

        # dev1 now connected, this should max out the first AP, causing the next
        # connection to fail to this AP.

        ordered_network = dev2.get_ordered_network("TestBlacklist", full_scan=True)

        self.assertEqual(ordered_network.type, NetworkType.psk)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network.network_object.connect()

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(dev2, condition)

        # We should have temporarily blacklisted the first BSS, and connected
        # to this one.
        bss_hostapd[1].wait_for_event('AP-STA-CONNECTED %s' % dev2.address)

        # Now check that the first BSS is still not blacklisted. We can
        # disconnect dev1, opening up the AP for more connections
        dev1.disconnect()
        dev2.disconnect()

        ordered_network = dev2.get_ordered_network("TestBlacklist")

        self.assertEqual(ordered_network.type, NetworkType.psk)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network.network_object.connect()

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(dev2, condition)

        bss_hostapd[2].wait_for_event('AP-STA-CONNECTED %s' % dev2.address)

        wd.unregister_psk_agent(psk_agent)

    def test_all_blacklisted(self):
        wd = self.wd
        bss_hostapd = self.bss_hostapd

        rule0 = self.rule0
        rule1 = self.rule1
        rule2 = self.rule2

        psk_agent = PSKAgent(["secret123", 'secret123'])
        wd.register_psk_agent(psk_agent)

        devices = wd.list_devices(1)
        device = devices[0]

        ordered_network = device.get_ordered_network("TestBlacklist")

        self.assertEqual(ordered_network.type, NetworkType.psk)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        # Have both APs drop all packets, both should get blacklisted
        rule0.drop = True
        rule0.enable = True
        rule1.drop = True
        rule1.enable = True
        rule2.drop = True
        rule2.enable = True

        with self.assertRaises(iwd.FailedEx):
            ordered_network.network_object.connect()

        rule0.drop = False
        rule1.drop = False
        rule2.drop = False

        # Wait for scanning (likely a quick-scan) to finish, otherwise we will
        # may not have all BSS's in the list.
        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        # This connect should work
        ordered_network.network_object.connect()

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        bss_hostapd[0].wait_for_event('AP-STA-CONNECTED %s' % device.address)

        wd.unregister_psk_agent(psk_agent)

    def test_invalid_password(self):
        wd = self.wd
        bss_hostapd = self.bss_hostapd

        psk_agent = PSKAgent("wrong_password")
        wd.register_psk_agent(psk_agent)

        devices = wd.list_devices(1)
        device = devices[0]

        ordered_network = device.get_ordered_network("TestBlacklist")

        self.assertEqual(ordered_network.type, NetworkType.psk)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        with self.assertRaises(iwd.FailedEx):
            ordered_network.network_object.connect()

        wd.unregister_psk_agent(psk_agent)

        psk_agent = PSKAgent("secret123")
        wd.register_psk_agent(psk_agent)

        ordered_network.network_object.connect()

        # We failed to connect bss_hostapd[0], but with a bad password. Verify
        # that this did not trigger a blacklist and that we did reconnect
        # successfully to bss_hostapd[0]
        self.assertIn(device.address, bss_hostapd[0].list_sta())

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        wd.unregister_psk_agent(psk_agent)

    def test_connection_success(self):
        wd = self.wd
        bss_hostapd = self.bss_hostapd
        rule0 = self.rule0

        psk_agent = PSKAgent("secret123")
        wd.register_psk_agent(psk_agent)

        devices = wd.list_devices(2)
        device = devices[0]

        devices[1].disconnect()

        ordered_network = device.get_ordered_network("TestBlacklist")

        self.assertEqual(ordered_network.type, NetworkType.psk)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        rule0.drop = True

        ordered_network.network_object.connect(wait=False)

        # Have AP1 drop all packets, should result in a connection timeout
        rule0.drop = True

        # Note the time so later we don't sleep any longer than required
        start = time.time()

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        # IWD should have attempted to connect to bss_hostapd[0], since its
        # signal strength was highest. But since we dropped all packets this
        # connect should fail, and the BSS should be blacklisted. Then we
        # should automatically try the next BSS in the list, which is
        # bss_hostapd[1]
        self.assertNotIn(device.address, bss_hostapd[0].list_sta())
        bss_hostapd[1].wait_for_event('AP-STA-CONNECTED %s' % device.address)

        rule0.drop = False

        device.disconnect()
        device.autoconnect = True

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        # Now we wait... AutoConnect should take over

        condition = 'obj.state == DeviceState.connecting'
        wd.wait_for_object_condition(device, condition)

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        # Same as before, make sure we didn't connect to the blacklisted AP.
        self.assertNotIn(device.address, bss_hostapd[0].list_sta())
        bss_hostapd[1].wait_for_event('AP-STA-CONNECTED %s' % device.address)

        # Wait for the blacklist to expire (10 seconds)
        elapsed = time.time() - start

        if elapsed < 15:
            wd.wait(15 - elapsed)

        device.disconnect()

        ordered_network = device.get_ordered_network("TestBlacklist", full_scan=True)

        self.assertEqual(ordered_network.type, NetworkType.psk)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network.network_object.connect()

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        bss_hostapd[0].wait_for_event('AP-STA-CONNECTED %s' % device.address)

        self.wd.unregister_psk_agent(psk_agent)

    def setUp(self):
        self.wd = IWD(True)

    def tearDown(self):
        IWD.clear_storage()
        self.wd = None

    @classmethod
    def setUpClass(cls):
        cls.hwsim = Hwsim()

        cls.bss_hostapd = [ HostapdCLI(config='ssid1.conf'),
                            HostapdCLI(config='ssid2.conf'),
                            HostapdCLI(config='ssid3.conf') ]
        cls.bss_radio =  [ cls.hwsim.get_radio('rad0'),
                       cls.hwsim.get_radio('rad1'),
                       cls.hwsim.get_radio('rad2') ]

        cls.rule0 = cls.hwsim.rules.create()
        cls.rule0.source = cls.bss_radio[0].addresses[0]
        cls.rule0.bidirectional = True
        cls.rule0.signal = -2000
        cls.rule0.enabled = True

        cls.rule1 = cls.hwsim.rules.create()
        cls.rule1.source = cls.bss_radio[1].addresses[0]
        cls.rule1.bidirectional = True
        cls.rule1.signal = -7000
        cls.rule1.enabled = True

        cls.rule2 = cls.hwsim.rules.create()
        cls.rule2.source = cls.bss_radio[2].addresses[0]
        cls.rule2.bidirectional = True
        cls.rule2.signal = -8000
        cls.rule2.enabled = True

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

        cls.hwsim.rules.remove_all()

if __name__ == '__main__':
    unittest.main(exit=True)
