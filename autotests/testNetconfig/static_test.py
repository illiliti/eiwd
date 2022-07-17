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

        ordered_network = dev1.get_ordered_network('ap-main')

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

        ifname = str(dev1.name)
        # Since we're in an isolated VM with freshly created interfaces we know any routes
        # will have been created by IWD and don't have to allow for pre-existing routes
        # in the table.
        # Flags: 1=RTF_UP, 2=RTF_GATEWAY
        expected_routes4 = {
                testutil.RouteInfo(gw=socket.inet_pton(socket.AF_INET, '192.168.1.3'),
                    flags=3, ifname=ifname),
                testutil.RouteInfo(dst=socket.inet_pton(socket.AF_INET, '192.168.1.0'), plen=25,
                    flags=1, ifname=ifname)
            }
        expected_routes6 = {
                testutil.RouteInfo(gw=socket.inet_pton(socket.AF_INET6, '3ffe:501:ffff:200::3'),
                    flags=3, ifname=ifname),
                testutil.RouteInfo(dst=socket.inet_pton(socket.AF_INET6, '3ffe:501:ffff:200::'), plen=80,
                    flags=1, ifname=ifname),
            }

        self.maxDiff = None
        self.assertEqual(expected_routes4, set(testutil.get_routes4(ifname)))
        self.assertEqual(expected_routes6, set(testutil.get_routes6(ifname)))

        rclog = open('/tmp/resolvconf.log', 'r')
        entries = rclog.readlines()
        rclog.close()
        expected_rclog = ['-a %s.dns\n' % ifname, 'nameserver 192.168.1.4\n', 'nameserver 3ffe:501:ffff:200::4\n']
        # Every resolvconf -a run overwrites the previous settings.  Check the last three lines
        # of the log since we care about the end result here.
        self.assertEqual(expected_rclog, entries[-3:])

        ordered_network = dev2.get_ordered_network('ap-main')

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

        hapd = HostapdCLI('ap-main.conf')
        # TODO: This could be moved into test-runner itself if other tests ever
        #       require this functionality (p2p, FILS, etc.). Since it's simple
        #       enough it can stay here for now.
        ctx.start_process(['ip', 'addr','add', '192.168.1.1/255.255.128.0',
                            'dev', hapd.ifname]).wait()
        ctx.start_process(['touch', '/tmp/dhcpd.leases']).wait()
        cls.dhcpd_pid = ctx.start_process(['dhcpd', '-f', '-cf', '/tmp/dhcpd.conf',
                                            '-lf', '/tmp/dhcpd.leases',
                                            hapd.ifname], cleanup=remove_lease)
        IWD.copy_to_storage('static.psk', '/tmp/storage', 'ap-main.psk')

        cls.orig_path = os.environ['PATH']
        os.environ['PATH'] = '/tmp/test-bin:' + os.environ['PATH']
        IWD.copy_to_storage('resolvconf', '/tmp/test-bin')

    @classmethod
    def tearDownClass(cls):
        cls.dhcpd_pid.kill()
        os.system('rm -rf /tmp/resolvconf.log /tmp/test-bin /tmp/storage')
        os.environ['PATH'] = cls.orig_path

if __name__ == '__main__':
    unittest.main(exit=True)
