#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD
import testutil
import subprocess

class Test(unittest.TestCase):

    def check_connection_success(self, ssid):
        device = self.wd.list_devices(1)[0]

        condition = 'not obj.scanning'
        self.wd.wait_for_object_condition(device, condition)

        ordered_network = device.get_ordered_network(ssid)

        condition = 'obj.connected'
        self.wd.wait_for_object_condition(ordered_network.network_object, condition)

        device.disconnect()

        condition = 'not obj.connected'
        self.wd.wait_for_object_condition(ordered_network.network_object, condition)

    def test_connection_with_passphrase(self):
        ssid = 'ssidPassphrase'

        device = self.wd.list_devices(1)[0]

        # Use --dontaks cmd-line option
        with self.assertRaises(subprocess.CalledProcessError):
                        subprocess.check_call(['iwctl', '-d', 'station',
                                                 device.name, 'connect', ssid])

        subprocess.check_call(['iwctl', '-P', 'passphrase',
                                'station', device.name, 'connect', ssid])

        self.check_connection_success(ssid)

    def test_connection_with_username_and_password(self):
        ssid = 'ssidUNameAndPWord'

        device = self.wd.list_devices(1)[0]

        subprocess.check_call(['iwctl', '-u', 'user', '-p', 'password',
                                'station', device.name, 'connect', ssid])

        self.check_connection_success(ssid)

    def test_connection_with_password(self):
        ssid = 'ssidPWord'

        device = self.wd.list_devices(1)[0]

        subprocess.check_call(['iwctl', '-p', 'password',
                                'station', device.name, 'connect', ssid])

        self.check_connection_success(ssid)

    def test_connection_failure(self):
        ssid = 'ssidPassphrase'

        device = self.wd.list_devices(1)[0]

        with self.assertRaises(subprocess.CalledProcessError):
                subprocess.check_call(['iwctl', '-P', 'incorrect_passphrase',
                                'station', device.name, 'connect', ssid])

    def test_invalid_command_line_option(self):
        ssid = 'ssidPassphrase'

        device = self.wd.list_devices(1)[0]

        with self.assertRaises(subprocess.CalledProcessError):
                subprocess.check_call(['iwctl', '-z',
                                'station', device.name, 'connect', ssid])

    def test_invalid_command(self):
        device = self.wd.list_devices(1)[0]

        with self.assertRaises(subprocess.CalledProcessError):
                subprocess.check_call(['iwctl', 'inexistent', 'command'])

    @classmethod
    def setUpClass(cls):
        IWD.copy_to_storage('ssidUNameAndPWord.8021x')
        IWD.copy_to_storage('ssidPWord.8021x')

        cls.wd = IWD()

        device = cls.wd.list_devices(1)[0]

        condition = 'not obj.scanning'
        cls.wd.wait_for_object_condition(device, condition)

        device.scan()

        condition = 'not obj.scanning'
        cls.wd.wait_for_object_condition(device, condition)

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
