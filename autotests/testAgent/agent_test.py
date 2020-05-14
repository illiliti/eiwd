#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import PSKAgent
from iwd import NetworkType
import testutil
import subprocess

class Test(unittest.TestCase):

    def check_connection(self, wd, ssid):

        device = wd.list_devices(1)[0]
        ordered_network = device.get_ordered_network(ssid, scan_if_needed=True)

        ordered_network.network_object.connect()

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        condition = 'obj.connected_network is not None'
        wd.wait_for_object_condition(device, condition)

        testutil.test_iface_operstate(device.name)
        device.disconnect()

        condition = 'obj.state == DeviceState.disconnected'
        wd.wait_for_object_condition(device, condition)

    def test_connection_with_no_agent(self):

        wd = IWD()

        with self.assertRaises(iwd.NoAgentEx):
            self.check_connection(wd, 'ssid1')

        IWD.clear_storage()

    def test_connection_with_own_agent(self):

        wd = IWD()

        psk_agent = PSKAgent("secret_ssid1")
        wd.register_psk_agent(psk_agent)

        self.check_connection(wd, 'ssid1')

        wd.unregister_psk_agent(psk_agent)

        IWD.clear_storage()

    def test_connection_with_other_agent(self):
        wd = IWD()

        iwctl = subprocess.Popen(['iwctl', '-P', 'secret_ssid2'])
        # Let iwctl to start and register its agent.
        wd.wait(2)

        self.check_connection(wd, 'ssid2')

        iwctl.terminate()
        iwctl.communicate()

        IWD.clear_storage()

    def test_connection_use_own_agent_from_multiple_registered(self):

        wd = IWD()

        iwctl = subprocess.Popen(['iwctl', '-P', 'secret_ssid2'])
        # Let iwctl to start and register its agent.
        wd.wait(2)

        psk_agent = PSKAgent("secret_ssid1")
        wd.register_psk_agent(psk_agent)

        self.check_connection(wd, 'ssid1')

        wd.unregister_psk_agent(psk_agent)

        iwctl.terminate()
        iwctl.communicate()

        IWD.clear_storage()

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
