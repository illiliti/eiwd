#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import PSKAgent
from hostapd import HostapdCLI
import testutil
import time

class TestConnectionAfterHiddenNetwork(unittest.TestCase):
    '''
    Tries to reproduce a memory leak caused by the consecutive calls to
    ConnectHiddenNetwork and Connect one after another.

    '''
    _ex = None
    _done = False

    def _success(self):
        self._done = True

    def _failure(self, ex):
        self._done = True
        self._ex = ex

    def test_connection(self):
        wd = IWD(True)

        psk_agent = PSKAgent("secret123")
        wd.register_psk_agent(psk_agent)

        device = wd.list_devices(1)[0]
        ordered_network = device.get_ordered_network('ssidOpen')

        device.connect_hidden_network_async(name='ssidSomeHidden',
                                                  reply_handler = self._success,
                                                  error_handler = self._failure)

        ordered_network.network_object.connect()

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        condition = 'obj.connected_network is not None'
        wd.wait_for_object_condition(device, condition)

        testutil.test_iface_operstate(device.name)
        device.disconnect()

        condition = 'obj.state == DeviceState.disconnected'
        wd.wait_for_object_condition(device, condition)

        wd.unregister_psk_agent(psk_agent)

        IWD.clear_storage()

        while not self._done:
            time.sleep(.300)

        if self._ex is not None:
            if self._ex.get_dbus_name() != 'net.connman.iwd.Failed':
                raise self._ex


    @classmethod
    def setUpClass(cls):
        cls.disabled = [HostapdCLI('ssidHiddenOpen.conf'),
                        HostapdCLI('ssidHiddenWPA.conf'),
                        HostapdCLI('ssidOverlap1.conf'),
                        HostapdCLI('ssidOverlap2.conf')]

        for hapd in cls.disabled:
            hapd.disable()

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

        for hapd in cls.disabled:
            hapd.reload()

if __name__ == '__main__':
    unittest.main(exit=True)
