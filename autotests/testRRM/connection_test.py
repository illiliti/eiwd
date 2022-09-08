#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import PSKAgent
from iwd import NetworkType
from hostapd import HostapdCLI
import testutil

# Table beacon with wildcard BSSID
basic_beacon = '51000000000002ffffffffffff020100'
# Table beacon with wildcard BSSID and SSID filter
beacon_with_ssid = '51000000000002ffffffffffff02010000077373696452524d'
# Passive beacon with wildcard BSSID
beacon_passive = '510b0000000000ffffffffffff020100'
# Active beacon with wildcard BSSID
beacon_active = '510b0000000001ffffffffffff020100'
# Passive beacon with duration set
beacon_passive_duration = '510b0000c80000ffffffffffff020100'
# Passive beacon on disabled frequency (disallowed in US)
beacon_passive_disabled = '520e0000c80000ffffffffffff020100'

class Test(unittest.TestCase):

    def test_connection_success(self):
        hapd = HostapdCLI(config='ssidRRM.conf')
        wd = IWD()

        psk_agent = PSKAgent("secret123")
        wd.register_psk_agent(psk_agent)

        devices = wd.list_devices(1)
        device = devices[0]

        ordered_network = device.get_ordered_network('ssidRRM')

        self.assertEqual(ordered_network.type, NetworkType.psk)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network.network_object.connect()

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        testutil.test_iface_operstate()
        testutil.test_ifaces_connected()

        hapd.wait_for_event('AP-STA-CONNECTED')

        wd.wait(1)

        # This should return both APs
        hapd.req_beacon(device.address, basic_beacon)

        for e in ['BEACON-RESP-RX', 'BEACON-RESP-RX']:
            event = hapd.wait_for_event(e).split(' ')
            self.assertTrue(event[3] == '00')

        wd.wait(1)

        # This should return just ssidRRM
        hapd.req_beacon(device.address, beacon_with_ssid)
        event = hapd.wait_for_event('BEACON-RESP-RX').split(' ')
        self.assertTrue(event[3] == '00')

        wd.wait(1)

        # This should passive scan on channel 11, returning otherSSID
        hapd.req_beacon(device.address, beacon_passive)
        # TODO: See if we are scanning here (scan not initiated from station)

        event = hapd.wait_for_event('BEACON-RESP-RX').split(' ')
        self.assertTrue(event[3] == '00')

        wd.wait(1)

        # This should active scan on channel 11, returning otherSSID
        hapd.req_beacon(device.address, beacon_active)
        # TODO: See if we are scanning here (scan not initiated from station)

        event = hapd.wait_for_event('BEACON-RESP-RX').split(' ')
        self.assertTrue(event[3] == '00')

        wd.wait(1)

         # This should passive scan on channel 11, returning otherSSID
        hapd.req_beacon(device.address, beacon_passive_duration)
        # TODO: See if we are scanning here (scan not initiated from station)

        event = hapd.wait_for_event('BEACON-RESP-RX').split(' ')
        self.assertTrue(event[3] == '00')

        wd.wait(1)

        hapd.req_beacon(device.address, beacon_passive_disabled)

        event = hapd.wait_for_event('BEACON-RESP-RX').split(' ')
        self.assertTrue(event[3] != '00')

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        wd.unregister_psk_agent(psk_agent)

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
