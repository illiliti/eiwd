#! /usr/bin/python3

import unittest

from iwd import IWD

class Test(unittest.TestCase):
    def test_ap_scan(self):
        wd = IWD(True)

        dev = wd.list_devices(1)[0]

        dev.start_ap('TestAP2', 'Password2')

        dev.scan()

        networks = dev.get_ordered_networks()

        self.assertTrue(len(networks) == 1)
        self.assertTrue(networks[0]['Name'] == 'TestAP1')
