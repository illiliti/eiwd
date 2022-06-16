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
        # Use a non-default storage_dir for one of the instances, the default for the other one
        wd = IWD(True, iwd_storage_dir='/tmp/storage')

        ns0 = ctx.get_namespace('ns0')

        wd_ns0 = IWD(True, namespace=ns0)

        psk_agent = PSKAgent("secret123")
        psk_agent_ns0 = PSKAgent("secret123", namespace=ns0)
        wd.register_psk_agent(psk_agent)
        wd_ns0.register_psk_agent(psk_agent_ns0)

        dev1 = wd.list_devices(1)[0]
        dev2 = wd_ns0.list_devices(1)[0]

        ordered_network = dev1.get_ordered_network('ssidTKIP')

        self.assertEqual(ordered_network.type, NetworkType.psk)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network.network_object.connect()

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(dev1, condition)

        testutil.test_iface_operstate()
        testutil.test_ifaces_connected()

        testutil.test_ip_address_match(dev1.name, '192.168.1.10', 25)
        testutil.test_ip_address_match(dev1.name, '3ffe:501:ffff:200::10', 80)

        ordered_network = dev2.get_ordered_network('ssidTKIP')

        condition = 'not obj.connected'
        wd_ns0.wait_for_object_condition(ordered_network.network_object, condition)

        # Connect to the same network from a dynamically configured client.  The
        # DHCP server doesn't know (even though dev1 announced itself) that
        # 192.168.1.10 is already in use and if it assigns dev2 the lowest
        # available address, that's going to be 192.168.1.10.  dev1's ACD
        # implementation should then stop using this address.
        ordered_network.network_object.connect()

        condition = 'obj.state == DeviceState.connected'
        wd_ns0.wait_for_object_condition(dev2, condition)

        wd.wait(1)
        # Check dev1 is now disconnected or without its IPv4 address
        if dev1.state == iwd.DeviceState.connected:
            testutil.test_ip_address_match(dev1.name, None)

        dev1.disconnect()
        dev2.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        wd.unregister_psk_agent(psk_agent)

    @classmethod
    def setUpClass(cls):
        def remove_lease():
            try:
                os.remove('/tmp/dhcpd.leases')
                os.remove('/tmp/dhcpd.leases~')
            except:
                pass

        hapd = HostapdCLI()
        # TODO: This could be moved into test-runner itself if other tests ever
        #       require this functionality (p2p, FILS, etc.). Since it's simple
        #       enough it can stay here for now.
        ctx.start_process(['ip', 'addr','add', '192.168.1.1/255.255.128.0',
                            'dev', hapd.ifname]).wait()
        ctx.start_process(['touch', '/tmp/dhcpd.leases']).wait()
        cls.dhcpd_pid = ctx.start_process(['dhcpd', '-f', '-cf', '/tmp/dhcpd.conf',
                                            '-lf', '/tmp/dhcpd.leases',
                                            hapd.ifname], cleanup=remove_lease)
        IWD.copy_to_storage('ssidTKIP.psk', '/tmp/storage')

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage(storage_dir='/tmp/storage')
        cls.dhcpd_pid.kill()

if __name__ == '__main__':
    unittest.main(exit=True)
