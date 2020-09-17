#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
from iwd import IWD
from config import ctx

from ead import EAD

class Test(unittest.TestCase):
    def test_connection_success(self):
        ctx.start_process(['ead', '-i', 'eth1', '-d'])

        ead = EAD()

        adapter = ead.list_adapters(1)[0]

        condition = 'obj.connected == True'
        ead.wait_for_object_condition(adapter, condition)

        condition = 'obj.authenticated == True'
        ead.wait_for_object_condition(adapter, condition)

    @classmethod
    def setUpClass(cls):
        IWD.copy_to_storage('default.8021x', storage_dir='/var/lib/ead')

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
