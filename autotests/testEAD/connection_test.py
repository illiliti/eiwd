#!/usr/bin/python3

import unittest
import sys
import os
import shutil

sys.path.append('../util')
from iwd import IWD
from config import ctx

from ead import EAD

class Test(unittest.TestCase):
    def test_connection_success(self):
        env = os.environ.copy()
        env['STATE_DIRECTORY'] = '/tmp/ead'
        p = ctx.start_process(['ead', '-i', 'eth1', '-d'], env=env)

        ead = EAD()

        adapter = ead.list_adapters(1)[0]

        condition = 'obj.connected == True'
        ead.wait_for_object_condition(adapter, condition)

        condition = 'obj.authenticated == True'
        ead.wait_for_object_condition(adapter, condition)

        ctx.stop_process(p)
    @classmethod
    def setUpClass(cls):
        os.mkdir('/tmp/ead')

        IWD.copy_to_storage('default.8021x', storage_dir='/tmp/ead')

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage(storage_dir='/tmp/ead')

        shutil.rmtree('/tmp/ead')

if __name__ == '__main__':
    unittest.main(exit=True)
