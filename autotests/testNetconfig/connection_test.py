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
import datetime, time

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

        def get_ll_addrs6(ns, ifname):
            show_ip = ns.start_process(['ip', 'addr', 'show', ifname])
            show_ip.wait()
            for l in show_ip.out.split('\n'):
                if 'inet6 fe80::' in l:
                    return socket.inet_pton(socket.AF_INET6, l.split(None, 1)[1].split('/', 1)[0])
            return None

        wd = IWD(True)

        psk_agent = PSKAgent("secret123")
        wd.register_psk_agent(psk_agent)

        devices = wd.list_devices(1)
        device = devices[0]

        ordered_network = device.get_ordered_network('ap-ns1')

        self.assertEqual(ordered_network.type, NetworkType.psk)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network.network_object.connect()

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)
        connect_time = time.time()

        testutil.test_iface_operstate()

        testutil.test_ip_address_match(device.name, '192.168.1.10', 17, 24)
        ctx.non_block_wait(check_addr, 10, device,
                            exception=Exception("IPv6 address was not set"))

        # Cannot use test_ifaces_connected() across namespaces (implementation details)
        testutil.test_ip_connected(('192.168.1.10', ctx), ('192.168.1.1', self.ns1))

        ifname = str(device.name)
        router_ll_addr = get_ll_addrs6(self.ns1, self.hapd.ifname)
        # Since we're in an isolated VM with freshly created interfaces we know any routes
        # will have been created by IWD and we don't have to allow for pre-existing routes
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
                # Router for an off-link prefix, medium preference
                testutil.RouteInfo(dst=socket.inet_pton(socket.AF_INET6, '3ffe:501:ffff:300::'), plen=64,
                    gw=router_ll_addr, flags=3, ifname=ifname),
                # Router for an off-link prefix, high preference
                testutil.RouteInfo(dst=socket.inet_pton(socket.AF_INET6, '3ffe:501:ffff:400::'), plen=65,
                    gw=router_ll_addr, flags=3, ifname=ifname),
                # Router for an off-link prefix, low preference
                testutil.RouteInfo(dst=socket.inet_pton(socket.AF_INET6, '3ffe:501:ffff:500::'), plen=66,
                    gw=router_ll_addr, flags=3, ifname=ifname)
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

        leases_file = self.parse_lease_file('/tmp/dhcpd.leases', socket.AF_INET)
        lease = leases_file['leases'][socket.inet_pton(socket.AF_INET, '192.168.1.10')]
        self.assertEqual(lease['state'], 'active')
        self.assertTrue(lease['starts'] < connect_time)
        self.assertTrue(lease['ends'] > connect_time)
        # The T1 is 15 seconds per dhcpd.conf.  This is the approximate interval between lease
        # renewals we should see from the client (+/- 1 second + some jitter).  Wait a little
        # less than twice that time (25s) so that we can expect the lease was renewed strictly
        # once (not 0 or 2 times) by that time, check that the lease timestamps have changed by
        # at least 10s so as to leave a lot of margin.
        renew_time = lease['starts'] + 15
        now = time.time()
        ctx.non_block_wait(lambda: False, renew_time + 10 - now, exception=False)

        leases_file = self.parse_lease_file('/tmp/dhcpd.leases', socket.AF_INET)
        new_lease = leases_file['leases'][socket.inet_pton(socket.AF_INET, '192.168.1.10')]
        self.assertEqual(new_lease['state'], 'active')
        self.assertTrue(new_lease['starts'] > lease['starts'] + 10)
        self.assertTrue(new_lease['starts'] < lease['starts'] + 25)
        self.assertTrue(new_lease['ends'] > lease['ends'] + 10)
        self.assertTrue(new_lease['ends'] < lease['ends'] + 25)

        # Now wait another T1 seconds but don't let our DHCP client get its REQUEST out this
        # time so as to test renew timeouts and resends.  The retry interval is 60 seconds
        # since (T2 - T1) / 2 is shorter than 60s.  It is now about 10s since the last
        # renewal or 5s before the next DHCPREQUEST frame that is going to be lost.  We'll
        # wait T1 seconds, so until about 10s after the failed attempt, we'll check that
        # there was no renewal by that time, just in case, and we'll reenable frame delivery.
        # We'll then wait another 60s and we should see the lease has been successfully
        # renewed some 10 seconds earlier on the 1st DHCPREQUEST retransmission.
        #
        # We can't use hswim to block the frames from reaching the AP because we'd lose
        # beacons and get disconnected.  We also can't drop our subnet route or IP address
        # because IWD's sendto() call would synchronously error out and the DHCP client
        # would just give up.  Add a false route to break routing to 192.168.1.1 and delete
        # it afterwards.
        os.system('ip route add 192.168.1.1/32 dev ' + ifname  + ' via 192.168.1.100 preference 0')

        lease = new_lease
        renew_time = lease['starts'] + 15
        now = time.time()
        ctx.non_block_wait(lambda: False, renew_time + 10 - now, exception=False)

        leases_file = self.parse_lease_file('/tmp/dhcpd.leases', socket.AF_INET)
        new_lease = leases_file['leases'][socket.inet_pton(socket.AF_INET, '192.168.1.10')]
        self.assertEqual(new_lease['starts'], lease['starts'])

        os.system('ip route del 192.168.1.1/32 dev ' + ifname  + ' via 192.168.1.100 preference 0')

        retry_time = lease['starts'] + 75
        now = time.time()
        ctx.non_block_wait(lambda: False, retry_time + 10 - now, exception=False)

        leases_file = self.parse_lease_file('/tmp/dhcpd.leases', socket.AF_INET)
        new_lease = leases_file['leases'][socket.inet_pton(socket.AF_INET, '192.168.1.10')]
        self.assertEqual(new_lease['state'], 'active')
        self.assertTrue(new_lease['starts'] > lease['starts'] + 70)
        self.assertTrue(new_lease['starts'] < lease['starts'] + 85)
        self.assertTrue(new_lease['ends'] > lease['ends'] + 70)
        self.assertTrue(new_lease['ends'] < lease['ends'] + 85)

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

        cls.ns1 = ctx.get_namespace('ns1')
        cls.hapd = HostapdCLI('ap-ns1.conf')
        # TODO: This could be moved into test-runner itself if other tests ever
        #       require this functionality (p2p, FILS, etc.). Since its simple
        #       enough it can stay here for now.
        cls.ns1.start_process(['ip', 'addr','add', '192.168.1.1/17',
                            'dev', cls.hapd.ifname]).wait()
        cls.ns1.start_process(['touch', '/tmp/dhcpd.leases']).wait()
        cls.dhcpd_pid = cls.ns1.start_process(['dhcpd', '-f', '-d', '-cf', '/tmp/dhcpd.conf',
                                                '-lf', '/tmp/dhcpd.leases',
                                                cls.hapd.ifname], cleanup=remove_lease4)

        cls.ns1.start_process(['ip', 'addr', 'add', '3ffe:501:ffff:100::1/72',
                            'dev', cls.hapd.ifname]).wait()
        cls.ns1.start_process(['touch', '/tmp/dhcpd6.leases']).wait()
        cls.dhcpd6_pid = cls.ns1.start_process(['dhcpd', '-6', '-f', '-d',
                                                '-cf', '/tmp/dhcpd-v6.conf',
                                                '-lf', '/tmp/dhcpd6.leases',
                                                cls.hapd.ifname], cleanup=remove_lease6)
        cls.ns1.start_process(['sysctl',
                                'net.ipv6.conf.' + cls.hapd.ifname + '.forwarding=1']).wait()
        # Send out Router Advertisements telling clients to use DHCPv6.
        # Note trying to send the RAs from the router's global IPv6 address by adding a
        # "AdvRASrcAddress { 3ffe:501:ffff:100::1; };" line will fail because the client
        # and the router interfaces are in the same namespace and Linux won't allow routes
        # with a non-link-local gateway address that is present on another interface in the
        # same namespace.
        config = open('/tmp/radvd.conf', 'w')
        config.write('interface ' + cls.hapd.ifname + ''' {
            AdvSendAdvert on;
            AdvManagedFlag on;
            prefix 3ffe:501:ffff:100::/72 { AdvAutonomous off; };
            route 3ffe:501:ffff:300::/64 {};
            route 3ffe:501:ffff:400::/65 { AdvRoutePreference low; };
            route 3ffe:501:ffff:500::/66 { AdvRoutePreference high; };
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
        cls.ns1.stop_process(cls.dhcpd6_pid)
        cls.dhcpd6_pid = None
        cls.ns1.stop_process(cls.radvd_pid)
        cls.radvd_pid = None
        os.system('rm -rf /tmp/radvd.conf /tmp/resolvconf.log /tmp/test-bin')
        os.environ['PATH'] = cls.orig_path

    @staticmethod
    def parse_lease_file(path, family):
        file = open(path, 'r')
        lines = file.readlines()
        file.close()

        stack = [[]]
        statement = []
        token = ''
        for line in lines:
            whitespace = False
            quote = False
            for ch in line:
                if not quote and ch in ' \t\r\n;{}=#':
                    if len(token):
                        statement.append(token)
                        token = ''
                if not quote and ch in ';{}':
                    if len(statement):
                        stack[-1].append(statement)
                        statement = []
                if ch == '"':
                    quote = not quote
                elif quote or ch not in ' \t\r\n;{}#':
                    token += ch
                if ch == '#':
                    break
                elif ch == '{':
                    stack.append([])
                elif ch == '}':
                    statements = stack.pop()
                    stack[-1][-1].append(statements)
            if len(token):
                statement.append(token)
                token = ''
        if len(statement):
            stack[-1].append(statement)
        statements = stack.pop(0)
        if len(stack):
            raise Exception('Unclosed block(s)')

        contents = {'leases':{}}
        for s in statements:
            if s[0] == 'lease':
                ip = socket.inet_pton(family, s[1])
                lease = {}
                for param in s[2]:
                    if param[0] in ('starts', 'ends', 'tstp', 'tsfp', 'atsfp', 'cltt'):
                        weekday = param[1]
                        year, month, day = param[2].split('/')
                        hour, minute, second = param[3].split(':')
                        dt = datetime.datetime(
                                int(year), int(month), int(day),
                                int(hour), int(minute), int(second),
                                tzinfo=datetime.timezone.utc)
                        lease[param[0]] = dt.timestamp()
                    elif param[0:2] == ['binding', 'state']:
                        lease['state'] = param[2]
                    elif param[0:2] == ['hardware', 'ethernet']:
                        lease['hwaddr'] = bytes([int(v, 16) for v in param[2].split(':')])
                    elif param[0] in ('preferred-life', 'max-life'):
                        lease[param[0]] = int(param[1])
                    elif param[0] in ('client-hostname'):
                        lease[param[0]] = param[1]
                contents['leases'][ip] = lease # New entries overwrite older ones
            elif s[0] == 'server-duid':
                contents[s[0]] = s[1]
        return contents

if __name__ == '__main__':
    unittest.main(exit=True)
