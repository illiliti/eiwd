#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import PSKAgent
from iwd import NetworkType
from hostapd import HostapdCLI
import testutil
from config import ctx
import os

class Test(unittest.TestCase):

    def test_connection_success(self):
        wd = IWD(True)

        psk_agent = PSKAgent("secret123")
        wd.register_psk_agent(psk_agent)

        devices = wd.list_devices(1)
        device = devices[0]

        ordered_network = device.get_ordered_network('ssidTKIP')

        self.assertEqual(ordered_network.type, NetworkType.psk)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network.network_object.connect()

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        testutil.test_iface_operstate()
        testutil.test_ifaces_connected()

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        wd.unregister_psk_agent(psk_agent)

    @classmethod
    def setUpClass(cls):
        hapd = HostapdCLI()
        # TODO: This could be moved into test-runner itself if other tests ever
        #       require this functionality (p2p, FILS, etc.). Since its simple
        #       enough it can stay here for now.
        ctx.start_process(['ifconfig', hapd.ifname, '192.168.1.1', 'netmask', '255.255.255.0'],
                                wait=True)
        ctx.start_process(['touch', '/tmp/dhcpd.leases'], wait=True)
        cls.dhcpd_pid = ctx.start_process(['dhcpd', '-f', '-cf', '/tmp/dhcpd.conf',
                                            '-lf', '/tmp/dhcpd.leases',
                                            hapd.ifname])

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()
        ctx.stop_process(cls.dhcpd_pid)
        cls.dhcpd_pid = None
        os.remove('/tmp/dhcpd.leases')

if __name__ == '__main__':
    unittest.main(exit=True)
