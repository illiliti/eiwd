#! /usr/bin/python3

import unittest
import sys
import sys
import os
from fake_ap import AP

sys.path.append('../util')
from iwd import IWD

# Probe frame that causes IWD to crash
beacon=b'\xdd\nPo\x9a\t\x0e\x00\x00\x19\x10\x00\xdd/Po\x9a\t\x0c\x02\x00\x00\xdd\x05\x03\x03\x03Po\x9a\x10\x00\x0b\x05\x0e\x00\x00\x00\x00\x0b\x05\x00\x00\x00\xdd\x05\x00\x03\x03\x03\x03\x00\x00\x00\xdd\x05\x03\x03\x03\x03\x03'

class Test(unittest.TestCase):
    def test_beacon_crash(self):
        wd = IWD(True)

        devs = wd.list_devices()

        self.assertEqual(len(devs), 1)

        devs[0].autoconnect = True

        os.system("iw phy rad1 interface add wlan1 type managed")

        ap = AP("evilAP", "password1234", mode="iface", iface="wlan1", channel=4)
        ap.start(beacon)

        condition = "obj.scanning == True"
        wd.wait_for_object_condition(devs[0], condition)

        condition = "obj.scanning == False"
        wd.wait_for_object_condition(devs[0], condition)

if __name__ == '__main__':
    unittest.main(exit=True)
