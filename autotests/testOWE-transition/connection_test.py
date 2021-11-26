#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import NetworkType
from hostapd import HostapdCLI
from hwsim import Hwsim
import testutil

class Test(unittest.TestCase):

    def validate(self, wd, target, autoconnect=False, connect_hidden=False):
        devices = wd.list_devices(1)
        device = devices[0]
        device.autoconnect = autoconnect

        if not autoconnect:
            if not connect_hidden:
                condition = 'not obj.scanning'
                wd.wait_for_object_condition(device, condition)

                device.scan()

                condition = 'obj.scanning'
                wd.wait_for_object_condition(device, condition)

                condition = 'not obj.scanning'
                wd.wait_for_object_condition(device, condition)

                network = device.get_ordered_network('transition', scan_if_needed=False)

                network.network_object.connect()
            else:
                device.connect_hidden_network('owe-hidden')

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        testutil.test_iface_operstate()

        if type(target) != list:
            testutil.test_ifaces_connected(device.name, target.ifname)
            self.assertIn(device.address, target.list_sta())
        else:
            found = False
            for t in target:
                if device.address in t.list_sta():
                    testutil.test_ifaces_connected(device.name, t.ifname)
                    found = True

            self.assertTrue(found)

        device.disconnect()

    # Normal success case
    def test_owe_transition(self):
        self.hapd_open.set_value('vendor_elements', 'dd15506f9a1c02000000f1000a6f77652d68696464656e')
        self.hapd_open.reload()
        self.hapd_owe.set_value('vendor_elements', 'dd15506f9a1c02000000f0000a7472616e736974696f6e')
        self.hapd_owe.reload()

        self.hapd_owe2.disable()
        self.hapd_open2.disable()

        self.validate(self.wd, self.hapd_owe)

    # Normal success case
    def test_owe_transition_multi_network(self):
        self.hapd_open.set_value('vendor_elements', 'dd15506f9a1c02000000f1000a6f77652d68696464656e')
        self.hapd_open.reload()
        self.hapd_owe.set_value('vendor_elements', 'dd15506f9a1c02000000f0000a7472616e736974696f6e')
        self.hapd_owe.reload()

        self.hapd_open2.set_value('vendor_elements', 'dd17506f9a1c02000000f1000c6f77652d68696464656e2d32')
        self.hapd_open2.set_value('ssid', 'transition-2')
        self.hapd_open2.reload()
        self.hapd_owe2.set_value('vendor_elements', 'dd17506f9a1c02000000f0000c7472616e736974696f6e2d32')
        self.hapd_owe2.set_value('ssid', 'owe-hidden-2')
        self.hapd_owe2.reload()

        self.validate(self.wd, self.hapd_owe)

    # Two pairs of open/OWE BSS's (OWE BSS's have different SSIDs) */
    def test_owe_transition_multi_bss(self):
        self.hapd_open.set_value('vendor_elements', 'dd15506f9a1c02000000f1000a6f77652d68696464656e')
        self.hapd_open.reload()
        self.hapd_owe.set_value('vendor_elements', 'dd15506f9a1c02000000f0000a7472616e736974696f6e')
        self.hapd_owe.reload()

        self.hapd_open2.set_value('vendor_elements', 'dd17506f9a1c02000000f3000c6f77652d68696464656e2d32')
        self.hapd_open2.set_value('ssid', 'transition')
        self.hapd_open2.reload()
        self.hapd_owe2.set_value('vendor_elements', 'dd15506f9a1c02000000f2000a7472616e736974696f6e')
        self.hapd_owe2.set_value('ssid', 'owe-hidden-2')
        self.hapd_owe2.reload()

        self.validate(self.wd, [self.hapd_owe, self.hapd_owe2])

    # Two pairs of open/OWE BSS's (OWE BSS's have same SSID) */
    def test_owe_transition_multi_bss_same_ssid(self):
        self.hapd_open.set_value('vendor_elements', 'dd15506f9a1c02000000f1000a6f77652d68696464656e')
        self.hapd_open.reload()
        self.hapd_owe.set_value('vendor_elements', 'dd15506f9a1c02000000f0000a7472616e736974696f6e')
        self.hapd_owe.reload()

        self.hapd_open2.set_value('vendor_elements', 'dd15506f9a1c02000000f3000a6f77652d68696464656e')
        self.hapd_open2.set_value('ssid', 'transition')
        self.hapd_open2.reload()
        self.hapd_owe2.set_value('vendor_elements', 'dd15506f9a1c02000000f2000a7472616e736974696f6e')
        self.hapd_owe2.set_value('ssid', 'owe-hidden')
        self.hapd_owe2.reload()

        self.validate(self.wd, [self.hapd_owe, self.hapd_owe2])

    # Normal success autoconnect case
    def test_owe_transition_autoconnect(self):
        self.hapd_open.set_value('vendor_elements', 'dd15506f9a1c02000000f1000a6f77652d68696464656e')
        self.hapd_open.reload()
        self.hapd_owe.set_value('vendor_elements', 'dd15506f9a1c02000000f0000a7472616e736974696f6e')
        self.hapd_owe.reload()

        self.hapd_owe2.disable()
        self.hapd_open2.disable()

        IWD.copy_to_storage('transition.open')

        self.validate(self.wd, self.hapd_owe, autoconnect=True)

    # Open BSS has invalid BSSID in OWE transition element
    # Expected connection to Open BSS
    def test_owe_transition_invalid_open_bssid(self):
        self.hapd_open.set_value('vendor_elements', 'dd15506f9a1c02000000ff000a6f77652d68696464656e')
        self.hapd_open.reload()
        self.hapd_owe.set_value('vendor_elements', 'dd15506f9a1c02000000f0000a7472616e736974696f6e')
        self.hapd_owe.reload()

        self.hapd_owe2.disable()
        self.hapd_open2.disable()

        self.validate(self.wd, self.hapd_open)

    # OWE BSS has invalid BSSID in OWE transition element
    # Expected connection to Open BSS
    def test_owe_transition_invalid_owe_bssid(self):
        self.hapd_open.set_value('vendor_elements', 'dd15506f9a1c02000000f1000a6f77652d68696464656e')
        self.hapd_open.reload()
        self.hapd_owe.set_value('vendor_elements', 'dd15506f9a1c02000000ff000a7472616e736974696f6e')
        self.hapd_owe.reload()

        self.hapd_owe2.disable()
        self.hapd_open2.disable()

        self.validate(self.wd, self.hapd_open)

    # No OWE hidden network exists
    # Expected connection to Open BSS
    def test_owe_transition_no_hidden_found(self):
        self.hapd_open.set_value('vendor_elements', 'dd15506f9a1c02000000f1000a6f77652d68696464656e')
        self.hapd_open.reload()
        self.hapd_owe.disable()

        self.hapd_owe2.disable()
        self.hapd_open2.disable()

        self.validate(self.wd, self.hapd_open)

    # Directly connect to valid OWE hidden network
    # Expected connection failure
    def test_owe_transition_connect_hidden_valid(self):
        self.hapd_open.set_value('vendor_elements', 'dd15506f9a1c02000000f1000a6f77652d68696464656e')
        self.hapd_open.reload()
        self.hapd_owe.set_value('vendor_elements', 'dd15506f9a1c02000000f0000a7472616e736974696f6e')
        self.hapd_owe.reload()

        self.hapd_owe2.disable()
        self.hapd_open2.disable()

        with self.assertRaises(iwd.NotFoundEx):
            self.validate(self.wd, self.hapd_owe, connect_hidden=True)

    # Directly connect to invalid OWE hidden network. The SSID in the OWE BSS
    # IE points to itself. And the Open BSS IE points to a non-existent SSID.
    # Expected connection failure
    def test_owe_transition_connect_hidden_invalid(self):
        self.hapd_open.set_value('vendor_elements', 'dd18506f9a1c02000000f1000d6e6f2d6f77652d68696464656e')
        self.hapd_open.reload()
        self.hapd_owe.set_value('vendor_elements', 'dd15506f9a1c02000000f0000a6f77652d68696464656e')
        self.hapd_owe.reload()

        self.hapd_owe2.disable()
        self.hapd_open2.disable()

        with self.assertRaises(iwd.NotFoundEx):
            self.validate(self.wd, self.hapd_owe, connect_hidden=True)

    def test_owe_transition_band_info(self):
        self.hapd_open.set_value('vendor_elements', 'dd17506f9a1c02000000f1000a6f77652d68696464656e5103')
        self.hapd_open.reload()
        self.hapd_owe.set_value('vendor_elements', 'dd15506f9a1c02000000f0000a7472616e736974696f6e')
        self.hapd_owe.set_value('channel', '3')
        self.hapd_owe.reload()

        self.hapd_owe2.disable()
        self.hapd_open2.disable()

        self.validate(self.wd, self.hapd_owe)

    def test_owe_transition_wrong_band_info(self):
        self.hapd_open.set_value('vendor_elements', 'dd17506f9a1c02000000f1000a6f77652d68696464656e5102')
        self.hapd_open.reload()
        self.hapd_owe.set_value('vendor_elements', 'dd15506f9a1c02000000f0000a7472616e736974696f6e')
        self.hapd_owe.set_value('channel', '3')
        self.hapd_owe.reload()

        self.hapd_owe2.disable()
        self.hapd_open2.disable()

        self.validate(self.wd, self.hapd_open)

    # OWE Transition pair + additional open network with the same SSID
    def test_owe_transition_extra_open(self):
        self.hapd_open.set_value('vendor_elements', 'dd15506f9a1c02000000f1000a6f77652d68696464656e')
        self.hapd_open.reload()
        self.hapd_owe.set_value('vendor_elements', 'dd15506f9a1c02000000f0000a7472616e736974696f6e')
        self.hapd_owe.reload()

        self.hapd_open2.set_value('ssid', 'transition')
        self.hapd_open2.reload()

        self.hapd_owe2.disable()

        # Set the open network signal strength very low so it gets put last on
        # the network bss_list, forcing the additional open network to be
        # checked first.
        self.rule0 = self.hwsim.rules.create()
        self.rule0.source = self.hwsim.get_radio('rad0').addresses[0]
        self.rule0.signal = -4000
        self.rule0.enabled = True

        devices = self.wd.list_devices(1)
        device = devices[0]

        device.scan()
        condition = 'obj.scanning'
        self.wd.wait_for_object_condition(device, condition)
        condition = 'not obj.scanning'
        self.wd.wait_for_object_condition(device, condition)


        self.validate(self.wd, self.hapd_owe)

    def setUp(self):
        self.wd = IWD(True)
        self.hapd_owe = HostapdCLI(config='ssidOWE.conf')
        self.hapd_open = HostapdCLI(config='ssidOpen.conf')
        self.hapd_owe2 = HostapdCLI(config='ssidOWE-2.conf')
        self.hapd_open2 = HostapdCLI(config='ssidOpen-2.conf')

        self.hwsim = Hwsim()

    def tearDown(self):
        IWD.clear_storage()

        self.hapd_owe.set_value('channel', '1')

        self.wd = None
        self.hapd_open = None
        self.hapd_owe = None
        self.hwsim = None

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
