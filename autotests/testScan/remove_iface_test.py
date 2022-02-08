#!/usr/bin/python3

import unittest
import sys
import os

sys.path.append('../util')
from iwd import IWD
from config import ctx

class Test(unittest.TestCase):
    def test_connection_success(self):
        wd = IWD(True)

        devices = wd.list_devices(1)
        device = devices[0]

        device.autoconnect = True
        device.scan(wait=False)

        os.system('ifconfig %s down' % device.name)

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
