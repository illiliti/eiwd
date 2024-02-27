#!/usr/bin/python3

import unittest
import sys
import os
sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import PSKAgent
from iwd import NetworkType
from hostapd import HostapdCLI
import testutil

class Test(unittest.TestCase):

    def validate_connection(self, wd, rejected=False):
        devices = wd.list_devices(1)
        self.assertIsNotNone(devices)
        device = devices[0]

        device.autoconnect = True

        if rejected:
            device.wait_for_event("ecc-group-rejected", timeout=60)

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        wd.wait(2)

        testutil.test_iface_operstate(intf=device.name)
        testutil.test_ifaces_connected(if0=device.name, if1=self.hostapd.ifname)

        if not rejected:
            self.assertEqual(device.event_ocurred("ecc-group-rejected"), False)

        print(self.hostapd._get_status())

        sta_status = self.hostapd.sta_status(device.address)

        print(sta_status)

        self.assertEqual(int(sta_status["sae_group"]), 19)

        device.disconnect()

    # IWD should:
    #   - Connect, fail with group 20
    #   - Retry, succeed with group 19
    #   - Disconnect
    #   - Connect, try only group 19
    def test_auto_selection(self):
        IWD.copy_to_storage("profiles/ssidSAE.psk.default", name="ssidSAE.psk")
        self.validate_connection(self.wd, rejected=True)

        self.validate_connection(self.wd, rejected=False)

    # Try group 19 first
    def test_default_group_enabled(self):
        IWD.copy_to_storage("profiles/ssidSAE.psk.default_group", name="ssidSAE.psk")
        self.validate_connection(self.wd)

    # Same as auto-selection but won't retain the default group setting
    def test_default_group_disabled(self):
        IWD.copy_to_storage("profiles/ssidSAE.psk.most_secure", name="ssidSAE.psk")
        self.validate_connection(self.wd, rejected=True)

        # IWD should then retry but use only group 19
        self.validate_connection(self.wd, rejected=True)

    def setUp(self):
        self.hostapd.default()
        self.hostapd.set_value('sae_groups', '19')
        self.hostapd.set_value('sae_pwe', '0')
        self.hostapd.reload()
        self.hostapd.wait_for_event("AP-ENABLED")
        self.wd = IWD(True)

        self.wd.clear_storage()
        os.system("ls /tmp/iwd")

    def tearDown(self):
        self.wd.clear_storage()
        self.wd = None

    @classmethod
    def setUpClass(cls):
        cls.hostapd = HostapdCLI(config='ssidSAE.conf')
        cls.hostapd.default()

    @classmethod
    def tearDownClass(cls):
        pass

if __name__ == '__main__':
    unittest.main(exit=True)
