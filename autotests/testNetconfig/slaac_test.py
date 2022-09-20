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
                testutil.test_ip_address_match(device.name, '3ffe:501:ffff:200::', 128, 64)
            except:
                return False

            return True

        def get_ll_addrs6(ns, ifname):
            show_ip = ns.start_process(['ip', 'addr', 'show', ifname])
            show_ip.wait()
            for l in show_ip.out.split('\n'):
                if 'inet6 fe80::' in l:
                    return socket.inet_pton(socket.AF_INET6, l.split(None, 1)[1].split('/', 1)[0])
            return None

        IWD.copy_to_storage('auto.psk', name='ap-ns1.psk')
        wd = IWD(True)

        psk_agent = PSKAgent("secret123")
        wd.register_psk_agent(psk_agent)

        devices = wd.list_devices(1)
        device = devices[0]

        ordered_network = device.get_ordered_network('ap-ns1')

        self.assertEqual(ordered_network.type, NetworkType.psk)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        # Give the AP's interface time to set up addresses so that radvd can
        # reply to our Router Solicitation immediately.
        ctx.non_block_wait(lambda: False, 3, exception=False)

        ordered_network.network_object.connect()

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        testutil.test_iface_operstate()

        ctx.non_block_wait(check_addr, 10, device,
                            exception=Exception("IPv6 address was not set"))

        # Cannot use test_ifaces_connected() across namespaces (implementation details)
        testutil.test_ip_connected(('192.168.1.10', ctx), ('192.168.1.1', self.ns1))

        ifname = str(device.name)
        router_ll_addr = get_ll_addrs6(self.ns1, self.hapd.ifname)
        expected_routes6 = {
                # Default router
                testutil.RouteInfo(gw=router_ll_addr, flags=3, ifname=ifname),
                # On-link prefixes
                testutil.RouteInfo(dst=socket.inet_pton(socket.AF_INET6, '3ffe:501:ffff:100::'), plen=64,
                    flags=1, ifname=ifname),
                testutil.RouteInfo(dst=socket.inet_pton(socket.AF_INET6, '3ffe:501:ffff:200::'), plen=64,
                    flags=1, ifname=ifname),
            }
        self.maxDiff = None
        self.assertEqual(expected_routes6, set(testutil.get_routes6(ifname)))

        rclog = open('/tmp/resolvconf.log', 'r')
        entries = rclog.readlines()
        rclog.close()
        expected_rclog = ['-a %s.dns\n' % (ifname,), 'nameserver 192.168.1.2\n',
                'nameserver 3ffe:501:ffff:100::10\n', 'nameserver 3ffe:501:ffff:100::50\n',
                '-a %s.domain\n' % (ifname,), 'search test1\n', 'search test2\n']
        # Every resolvconf -a run overwrites the previous settings.  Check the last seven lines
        # of our log since we care about the end result here.
        self.assertEqual(expected_rclog, entries[-7:])

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
        cls.ns1 = ctx.get_namespace('ns1')
        cls.hapd = HostapdCLI('ap-ns1.conf')
        cls.ns1.start_process(['ip', 'addr','add', '192.168.1.1/17',
                            'dev', cls.hapd.ifname]).wait()
        cls.ns1.start_process(['touch', '/tmp/dhcpd.leases']).wait()
        cls.dhcpd_pid = cls.ns1.start_process(['dhcpd', '-f', '-d', '-cf', '/tmp/dhcpd.conf',
                                                '-lf', '/tmp/dhcpd.leases',
                                                cls.hapd.ifname], cleanup=remove_lease4)

        cls.ns1.start_process(['ip', 'addr', 'add', '3ffe:501:ffff:100::1/72',
                            'dev', cls.hapd.ifname]).wait()
        cls.ns1.start_process(['sysctl',
                                'net.ipv6.conf.' + cls.hapd.ifname + '.forwarding=1']).wait()
        config = open('/tmp/radvd.conf', 'w')
        config.write('interface ' + cls.hapd.ifname + ''' {
            AdvSendAdvert on;
            # Trick radvd to accept MinDelayBetweenRAs values less than 3 seconds.
            AdvHomeAgentFlag on;
            # Don't throttle so we can test solicited RA reception before link-local addr DAD done.
            # radvd may have sent an unsolicited RA just before our RS and would complain -- the
            # test should succeed regardless but will take some extra seconds.
            MinDelayBetweenRAs 0.05;
            AdvManagedFlag off;
            # Test that the prefix with longer lifetime is selected.
            prefix 3ffe:501:ffff:100::/64 { AdvAutonomous on; };
            prefix 3ffe:501:ffff:200::/64 { AdvAutonomous on; AdvPreferredLifetime infinity; AdvValidLifetime infinity; };
            RDNSS 3ffe:501:ffff:100::10 3ffe:501:ffff:100::50 { AdvRDNSSLifetime 3600; };
            DNSSL test1 test2 { AdvDNSSLLifetime 3600; };
            };''')
        config.close()
        cls.radvd_pid = cls.ns1.start_process(['radvd', '-n', '-d5',
                                                '-p', '/tmp/radvd.pid', '-C', '/tmp/radvd.conf'])

        cls.orig_path = os.environ['PATH']
        os.environ['PATH'] = '/tmp/test-bin:' + os.environ['PATH']
        IWD.copy_to_storage('resolvconf', '/tmp/test-bin')

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()
        cls.ns1.stop_process(cls.dhcpd_pid)
        cls.dhcpd_pid = None
        cls.ns1.stop_process(cls.radvd_pid)
        cls.radvd_pid = None
        os.system('rm -rf /tmp/radvd.conf /tmp/test-bin')
        os.environ['PATH'] = cls.orig_path

if __name__ == '__main__':
    unittest.main(exit=True)
