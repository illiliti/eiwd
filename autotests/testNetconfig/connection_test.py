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
import subprocess

class Test(unittest.TestCase):

    def test_connection_success(self):
        def check_addr(device):
            try:
                # DHCPv6 addresses always have a prefix length of 128 bits, the actual
                # subnet's prefix length is in the route.
                testutil.test_ip_address_match(device.name, '3ffe:501:ffff:100::1', 128, 112)
            except:
                return False

            return True

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

        testutil.test_ip_address_match(device.name, '192.168.1.10', 17, 24)
        ctx.non_block_wait(check_addr, 10, device,
                            exception=Exception("IPv6 address was not set"))

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        wd.unregister_psk_agent(psk_agent)

    @classmethod
    def setUpClass(cls):
        def remove_lease4():
            try:
                os.remove('/tmp/dhcpd.leases')
                os.remove('/tmp/dhcpd.leases~')
            except:
                pass
        def remove_lease6():
            try:
                os.remove('/tmp/dhcpd6.leases')
                os.remove('/tmp/dhcpd6.leases~')
            except:
                pass

        hapd = HostapdCLI()
        # TODO: This could be moved into test-runner itself if other tests ever
        #       require this functionality (p2p, FILS, etc.). Since its simple
        #       enough it can stay here for now.
        ctx.start_process(['ip', 'addr','add', '192.168.1.1/255.255.128.0',
                            'dev', hapd.ifname,]).wait()
        ctx.start_process(['touch', '/tmp/dhcpd.leases']).wait()
        cls.dhcpd_pid = ctx.start_process(['dhcpd', '-f', '-cf', '/tmp/dhcpd.conf',
                                            '-lf', '/tmp/dhcpd.leases',
                                            hapd.ifname], cleanup=remove_lease4)

        ctx.start_process(['ip', 'addr', 'add', '3ffe:501:ffff:100::1/72',
                            'dev', hapd.ifname]).wait()
        ctx.start_process(['touch', '/tmp/dhcpd6.leases']).wait()
        cls.dhcpd6_pid = ctx.start_process(['dhcpd', '-6', '-f', '-cf', '/tmp/dhcpd-v6.conf',
                                            '-lf', '/tmp/dhcpd6.leases',
                                            hapd.ifname], cleanup=remove_lease6)
        ctx.start_process(['sysctl', 'net.ipv6.conf.' + hapd.ifname + '.forwarding=1']).wait()
        # Tell clients to use DHCPv6
        config = open('/tmp/radvd.conf', 'w')
        config.write('interface ' + hapd.ifname + ' { AdvSendAdvert on; AdvManagedFlag on; };')
        config.close()
        cls.radvd_pid = ctx.start_process(['radvd', '-n', '-d5', '-p', '/tmp/radvd.pid', '-C', '/tmp/radvd.conf'])

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()
        ctx.stop_process(cls.dhcpd_pid)
        cls.dhcpd_pid = None
        ctx.stop_process(cls.dhcpd6_pid)
        cls.dhcpd6_pid = None
        ctx.stop_process(cls.radvd_pid)
        cls.radvd_pid = None
        os.remove('/tmp/radvd.conf')

if __name__ == '__main__':
    unittest.main(exit=True)
