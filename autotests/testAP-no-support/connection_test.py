#! /usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD

class Test(unittest.TestCase):
    def test_connection_success(self):
        wd = IWD()

        dev = wd.list_devices(1)[0]

        with self.assertRaises(iwd.NotSupportedEx):
            dev.start_ap('TestAP2', 'Password2')

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
