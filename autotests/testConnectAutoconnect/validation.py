#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import PSKAgent
from iwd import NetworkType

class TestConnectAutoConnect(unittest.TestCase):

    def check_connect(self, wd, device, ssid, throws):
        ordered_network = device.get_ordered_network(ssid, scan_if_needed=True)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        if not throws is None:
            with self.assertRaises(throws):
                ordered_network.network_object.connect()
            return
        else:
            ordered_network.network_object.connect()

        condition = 'obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

    def check_autoconnect(self, wd, device, ssid, throws):
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

    def validate_connection(self, wd, ssid, autoconnect, throws = None,
                                                            use_agent = False):
        if use_agent:
            psk_agent = PSKAgent("secret123")
            wd.register_psk_agent(psk_agent)

        devices = wd.list_devices(1)
        self.assertIsNotNone(devices)
        device = devices[0]

        if autoconnect:
            self.check_autoconnect(wd, device, ssid, throws)
        else:
            self.check_connect(wd, device, ssid, throws)

        if use_agent:
            wd.unregister_psk_agent(psk_agent)

    def validate(self, ssid, autoconnect, throws = None, use_agent = False):
        wd = IWD(True)

        self.validate_connection(wd, ssid, autoconnect, throws, use_agent)
