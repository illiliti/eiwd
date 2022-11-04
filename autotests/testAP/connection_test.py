#! /usr/bin/python3

import unittest
import os

from iwd import IWD
from config import ctx
from validation import validate, client_connect

class Test(unittest.TestCase):
    def test_connection_success(self):
        IWD.copy_to_storage('TestAP1.psk')

        wd = IWD(True)

        dev1, dev2 = wd.list_devices(2)

        client_connect(wd, dev1, 'TestAP1')

        dev1.start_ap('TestAP2', 'Password2')

        validate(wd, dev2, dev1, 'TestAP2', 'Password2')

        # Finally test dev1 can go to client mode and connect again
        client_connect(wd, dev1, 'TestAP1')

    def test_client_start_ap(self):
        IWD.copy_to_storage('TestAP1.psk')

        wd = IWD(True)

        dev1, dev2 = wd.list_devices(2)

        ctx.start_process(['iwctl', 'device', dev1.name, 'set-property', 'Mode', 'ap'], check=True)
        ctx.start_process(['iwctl', 'ap', dev1.name, 'start', 'TestAP2', 'Password2'], check=True)

        iwctl = ctx.start_process(['iwctl', 'ap', 'list'], check=True)

        self.assertIn(dev1.name, iwctl.out)

        iwctl = ctx.start_process(['iwctl', 'ap', dev1.name, 'show'], check=True)

        self.assertIn('TestAP2', iwctl.out)

        validate(wd, dev2, dev1, 'TestAP2', 'Password2')

    def test_valid_ciphers(self):
        ciphers = ['TKIP', 'CCMP-128', 'GCMP-128', 'CCMP-256', 'GCMP-256']

        for group in ciphers:
            for pairwise in ciphers:
                IWD.copy_to_ap('TestAP2.ap')
                os.system('echo "PairwiseCiphers=%s" >> /tmp/iwd/ap/TestAP2.ap' % pairwise)
                os.system('echo "GroupCipher=%s" >> /tmp/iwd/ap/TestAP2.ap' % group)

                wd = IWD(True)

                dev1, dev2 = wd.list_devices(2)

                dev1.start_ap('TestAP2')

                self.assertTrue(dev1.group_cipher == group)
                self.assertIn(pairwise, dev1.pairwise_ciphers)

                try:
                    validate(wd, dev2, dev1, 'TestAP2', 'Password2', ip_checks=False)
                except:
                    raise Exception("Failed with pairwise=%s group=%s" % (pairwise, group))
                finally:
                    IWD.clear_storage()
                    del wd

    def tearDown(self):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
