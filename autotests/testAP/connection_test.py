#! /usr/bin/python3

import unittest

from iwd import IWD
from validation import validate, client_connect

class Test(unittest.TestCase):
    def test_connection_success(self):
        wd = IWD(True)

        dev1, dev2 = wd.list_devices(2)

        client_connect(wd, dev1, 'TestAP1')

        dev1.start_ap('TestAP2', 'Password2')

        validate(wd, dev2, dev1, 'TestAP2', 'Password2')

        # Finally test dev1 can go to client mode and connect again
        client_connect(wd, dev1, 'TestAP1')

    @classmethod
    def setUpClass(cls):
        IWD.copy_to_storage('TestAP1.psk')

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
