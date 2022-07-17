#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import PSKAgent
from iwd import NetworkType

class TestHiddenNetworks(unittest.TestCase):

    def check_connect_hidden_network(self, wd, device, ssid, throws):
        if not throws is None:
            with self.assertRaises(throws):
                device.connect_hidden_network(ssid)
            return
        else:
            device.connect_hidden_network(ssid)

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

    def check_autoconnect_hidden_network(self, wd, device, ssid, throws):
        if throws is None:
            condition = 'obj.state == DeviceState.connected'
            wd.wait_for_object_condition(device, condition)

            condition = 'obj.connected_network is not None'
            wd.wait_for_object_condition(device, condition)

            ordered_network = device.get_ordered_network(ssid)

            self.assertTrue(ordered_network.network_object.connected)

            device.disconnect()

        condition = 'obj.state == DeviceState.disconnected'
        wd.wait_for_object_condition(device, condition)

    def validate_connection(self, wd, ssid, autoconnect, throws, use_agent,
                                                            wait_periodic_scan):
        if use_agent:
            psk_agent = PSKAgent(["secret123"], ('domain\\User', 'Password'))
            wd.register_psk_agent(psk_agent)

        devices = wd.list_devices(1)
        self.assertIsNotNone(devices)
        device = devices[0]
        device.autoconnect = autoconnect

        if autoconnect:
            self.check_autoconnect_hidden_network(wd, device, ssid, throws)
        else:
            if wait_periodic_scan:
                device.autoconnect = True
                condition = 'obj.scanning'
                wd.wait_for_object_condition(device, condition)
                condition = 'not obj.scanning'
                wd.wait_for_object_condition(device, condition)

            self.check_connect_hidden_network(wd, device, ssid, throws)

        if use_agent:
            wd.unregister_psk_agent(psk_agent)


    def validate(self, ssid, autoconnect, throws = None, use_agent = False,
                                                    wait_periodic_scan = False):
        wd = IWD(True)
        self.validate_connection(wd, ssid, autoconnect, throws, use_agent,
                                                        wait_periodic_scan)
