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
import socket

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

        ifname = str(device.name)
        router_ll_addr = [addr for addr, _, _ in testutil.get_addrs6(self.hapd.ifname) if addr[0:2] == b'\xfe\x80'][0]
        # Since we're in an isolated VM with freshly created interfaces we know any routes
        # will have been created by IWD and don't have to allow for pre-existing routes
        # in the table.
        # Flags: 1=RTF_UP, 2=RTF_GATEWAY
        expected_routes4 = {
                testutil.RouteInfo(gw=socket.inet_pton(socket.AF_INET, '192.168.1.1'),
                    flags=3, ifname=ifname),
                testutil.RouteInfo(dst=socket.inet_pton(socket.AF_INET, '192.168.0.0'), plen=17,
                    flags=1, ifname=ifname)
            }
        expected_routes6 = {
                # Default router
                testutil.RouteInfo(gw=router_ll_addr, flags=3, ifname=ifname),
                # On-link prefix
                testutil.RouteInfo(dst=socket.inet_pton(socket.AF_INET6, '3ffe:501:ffff:100::'), plen=72,
                    flags=1, ifname=ifname),
            }
        self.maxDiff = None
        self.assertEqual(expected_routes4, set(testutil.get_routes4(ifname)))
        self.assertEqual(expected_routes6, set(testutil.get_routes6(ifname)))

        rclog = open('/tmp/resolvconf.log', 'r')
        entries = rclog.readlines()
        rclog.close()
        expected_rclog = ['-a %s.dns\n' % ifname, 'nameserver 192.168.1.2\n', 'nameserver 3ffe:501:ffff:100::2\n']
        # Every real resolvconf -a run overwrites the previous settings.  Check the last three lines
        # of our log since we care about the end result here.
        self.assertEqual(expected_rclog, entries[-3:])

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
        cls.hapd = hapd
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
        # Send out Router Advertisements telling clients to use DHCPv6.
        # Note trying to send the RAs from the router's global IPv6 address by adding a
        # "AdvRASrcAddress { 3ffe:501:ffff:100::1; };" line will fail because the client
        # and the router interfaces are in the same namespace and Linux won't allow routes
        # with a non-link-local gateway address that is present on another interface in the
        # same namespace.
        config = open('/tmp/radvd.conf', 'w')
        config.write('interface ' + hapd.ifname + ''' {
            AdvSendAdvert on;
            AdvManagedFlag on;
            prefix 3ffe:501:ffff:100::/72 { AdvAutonomous off; };
            };''')
        config.close()
        cls.radvd_pid = ctx.start_process(['radvd', '-n', '-d5', '-p', '/tmp/radvd.pid', '-C', '/tmp/radvd.conf'])

        cls.orig_path = os.environ['PATH']
        os.environ['PATH'] = '/tmp/test-bin:' + os.environ['PATH']
        IWD.copy_to_storage('resolvconf', '/tmp/test-bin')

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()
        ctx.stop_process(cls.dhcpd_pid)
        cls.dhcpd_pid = None
        ctx.stop_process(cls.dhcpd6_pid)
        cls.dhcpd6_pid = None
        ctx.stop_process(cls.radvd_pid)
        cls.radvd_pid = None
        os.system('rm -rf /tmp/radvd.conf /tmp/resolvconf.log /tmp/test-bin')
        os.environ['PATH'] = cls.orig_path

if __name__ == '__main__':
    unittest.main(exit=True)
