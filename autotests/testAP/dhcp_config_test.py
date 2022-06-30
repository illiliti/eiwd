#! /usr/bin/python3

import unittest

from iwd import IWD
from config import ctx
from validation import validate

class Test(unittest.TestCase):
    def test_connection_success(self):
        # Using main.conf containing APRanges. The APConfig SSID should override
        # this range.
        wd = IWD(True, '/tmp/dhcp')

        ns0 = ctx.get_namespace('ns0')

        wd_ns0 = IWD(True, '/tmp/dhcp', namespace=ns0)

        dev1 = wd_ns0.list_devices(1)[0]
        dev2, dev3, dev4, dev5 = wd.list_devices(4)
        dev3.disconnect()
        dev4.disconnect()
        dev5.disconnect()

        dev1.start_ap('APConfig')

        validate(wd, dev2, dev1, 'APConfig', 'password123',
                    sta_ip_info=('192.168.1.3', ctx), ap_ip_info=('192.168.1.1', ns0))

    @classmethod
    def setUpClass(cls):
        IWD.copy_to_ap('dhcp/APConfig.ap')

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
