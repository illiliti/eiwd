#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import PSKAgent
from iwd import NetworkType

import testutil

from hostapd import HostapdCLI
from hwsim import Hwsim

class Test(unittest.TestCase):
    # Test that we do not periodically retry roaming if the transision looks
    # like this: LOW [roam] [new bss] HIGH.
    def test_stop_retry(self):
        hwsim = Hwsim()

        bss_hostapd = [ HostapdCLI(config='ssid1.conf'),
                        HostapdCLI(config='ssid2.conf') ]
        bss_radio =  [ hwsim.get_radio('rad0'),
                       hwsim.get_radio('rad1') ]

        rule0 = hwsim.rules.create()
        rule0.source = bss_radio[0].addresses[0]
        rule0.bidirectional = True
        rule0.enabled = True

        rule1 = hwsim.rules.create()
        rule1.source = bss_radio[1].addresses[0]
        rule1.bidirectional = True
        rule1.enabled = True

        HostapdCLI.group_neighbors(*bss_hostapd)

        # Start in the vicinity of BSS 0, check that iwd connects to BSS 0
        rule0.signal = -2000
        rule1.signal = -5000

        wd = IWD()

        psk_agent = PSKAgent("secret123")
        wd.register_psk_agent(psk_agent)

        devices = wd.list_devices(1)
        device = devices[0]

        ordered_network = device.get_ordered_network('TestRoamRetry', full_scan=True)

        self.assertEqual(ordered_network.type, NetworkType.psk)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network.network_object.connect()

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        bss_hostapd[0].wait_for_event('AP-STA-CONNECTED %s' % device.address)

        # Now push the signal below the RSSI threshold and check that iwd
        # connects to BSS 1
        rule0.signal = -8000

        # Check that iwd is on BSS 1 once out of roaming state and doesn't
        # go through 'disconnected', 'autoconnect', 'connecting' in between
        from_condition = 'obj.state == DeviceState.roaming'
        to_condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_change(device, from_condition, to_condition)

        bss_hostapd[1].wait_for_event('AP-STA-CONNECTED %s' % device.address)

        # Now make sure that we don't roam anymore. In order to catch this via
        # DeviceState, a suitable roaming target needs to be available. So jack
        # up the RSSI of BSS 0 again. The retry interval is 60 seconds, so we
        # should have roamed within that timeframe. Wait just a little longer
        # to account for the slowness of the autotest environment.
        rule0.signal = -2000

        condition = 'obj.state == DeviceState.roaming'
        self.assertRaises(TimeoutError, wd.wait_for_object_condition, device,
                          condition, max_wait=10)

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        wd.unregister_psk_agent(psk_agent)

        rule0.remove()
        rule1.remove()

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
