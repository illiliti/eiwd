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
import gc

class Test(unittest.TestCase):

    def test_connection_success(self):
        # Use a non-default storage_dir for one of the instances, the default for the other one
        iwd_main = IWD(True, iwd_storage_dir='/tmp/storage-main')
        psk_agent_main = PSKAgent("secret123")
        iwd_main.register_psk_agent(psk_agent_main)
        dev1 = iwd_main.list_devices(1)[0]

        ordered_network = dev1.get_ordered_network('ap-main')

        self.assertEqual(ordered_network.type, NetworkType.psk)

        condition = 'not obj.connected'
        iwd_main.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network.network_object.connect()

        condition = 'obj.state == DeviceState.connected'
        iwd_main.wait_for_object_condition(dev1, condition)

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

        # Run our second client in a separate namespace to allow ACD (ARP) to
        # work, and also be able to set identical IPs on both interfaces for
        # the next part of this test.
        ns0 = ctx.get_namespace('ns0')

        iwd_ns0_1 = IWD(True, namespace=ns0, iwd_storage_dir='/tmp/storage-ns0-1')
        psk_agent_ns0_1 = PSKAgent("secret123", namespace=ns0)
        iwd_ns0_1.register_psk_agent(psk_agent_ns0_1)
        dev2 = iwd_ns0_1.list_devices(1)[0]

        ordered_network = dev2.get_ordered_network('ap-main')

        condition = 'not obj.connected'
        iwd_ns0_1.wait_for_object_condition(ordered_network.network_object, condition)

        # Attempt a connection to the same AP that iwd_main is connected to
        # using the same static config.  The new client's ACD client should
        # detect an IP conflict and not allow the device to reach the
        # "connected" state although the DBus .Connect call will succeed.
        ordered_network.network_object.connect()
        self.assertEqual(dev2.state, iwd.DeviceState.connecting)
        try:
            # We should either stay in "connecting" indefinitely or move to
            # "disconnecting"
            condition = 'obj.state != DeviceState.connecting'
            iwd_ns0_1.wait_for_object_condition(dev2, condition, max_wait=21)
            self.assertEqual(dev2.state, iwd.DeviceState.disconnecting)
        except TimeoutError:
            dev2.disconnect()

        iwd_ns0_1.unregister_psk_agent(psk_agent_ns0_1)
        del dev2
        # Note: if any references to iwd_ns0_1 are left, the "del iwd_ns0_1"
        # will not kill the IWD process the iwd_ns0_2 initialization will raise
        # an exception.  The iwd_ns0_1.wait_for_object_condition() above
        # creates a circular reference (which is not wrong in itself) and
        # gc.collect() gets rid of it.  The actual solution is to eventually
        # avoid executing anything important in .__del__ (which is wrong.)
        gc.collect()
        del iwd_ns0_1

        iwd_ns0_2 = IWD(True, namespace=ns0, iwd_storage_dir='/tmp/storage-ns0-2')
        psk_agent_ns0_2 = PSKAgent("secret123", namespace=ns0)
        iwd_ns0_2.register_psk_agent(psk_agent_ns0_2)
        dev2 = iwd_ns0_2.list_devices(1)[0]

        ordered_network = dev2.get_ordered_network('ap-main')

        condition = 'not obj.connected'
        iwd_ns0_2.wait_for_object_condition(ordered_network.network_object, condition)

        # Connect to the same network from a dynamically configured client.  We
        # block ICMP pings so that the DHCP server can't confirm that
        # 192.168.1.10 is in use by dev1 and if it assigns dev2 the lowest
        # available address, that's going to be 192.168.1.10.  We also keep the
        # second client's netdev in a separate namespace so that the kernel
        # lets us assign the same IP.  dev1's ACD implementation should then
        # stop using this address.  Yes, a quite unrealistic scenario but this
        # lets us test our reaction to a conflict appearing after successful
        # initial setup.
        os.system("echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all")
        ordered_network.network_object.connect()

        condition = 'obj.state == DeviceState.connected'
        iwd_ns0_2.wait_for_object_condition(dev2, condition)

        iwd_main.wait(1)
        # Check dev1 is now disconnected or without its IPv4 address
        if dev1.state == iwd.DeviceState.connected:
            testutil.test_ip_address_match(dev1.name, None)

        dev1.disconnect()
        dev2.disconnect()

        condition = 'not obj.connected'
        iwd_main.wait_for_object_condition(ordered_network.network_object, condition)

        iwd_main.unregister_psk_agent(psk_agent_main)

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
        IWD.copy_to_storage('static.psk', '/tmp/storage-main', 'ap-main.psk')
        IWD.copy_to_storage('static.psk', '/tmp/storage-ns0-1', 'ap-main.psk')

        cls.orig_path = os.environ['PATH']
        os.environ['PATH'] = '/tmp/test-bin:' + os.environ['PATH']
        IWD.copy_to_storage('resolvconf', '/tmp/test-bin')

    @classmethod
    def tearDownClass(cls):
        cls.dhcpd_pid.kill()
        os.system('rm -rf /tmp/resolvconf.log /tmp/test-bin /tmp/storage-*')
        os.environ['PATH'] = cls.orig_path

if __name__ == '__main__':
    unittest.main(exit=True)
