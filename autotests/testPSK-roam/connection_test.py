#! /usr/bin/python3

import unittest
import sys, os

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import PSKAgent
from iwd import NetworkType
from hwsim import Hwsim
from hostapd import HostapdCLI
import testutil

class Test(unittest.TestCase):
    def validate_connection(self, wd, over_ds=False, pkt_loss=False):
        device = wd.list_devices(1)[0]

        ordered_network = device.get_ordered_network('TestFT', full_scan=True)

        self.assertEqual(ordered_network.type, NetworkType.psk)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        self.assertFalse(self.bss_hostapd[0].list_sta())
        self.assertFalse(self.bss_hostapd[1].list_sta())

        device.connect_bssid(self.bss_hostapd[0].bssid)

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        self.bss_hostapd[0].wait_for_event('AP-STA-CONNECTED %s' % device.address)

        testutil.test_iface_operstate(device.name)
        testutil.test_ifaces_connected(self.bss_hostapd[0].ifname, device.name)
        self.assertRaises(Exception, testutil.test_ifaces_connected,
                          (self.bss_hostapd[1].ifname, device.name, True, True))

        if over_ds:
            self.rule0.enabled = True

        if pkt_loss:
            # Drop all data frames
            self.rule1.enabled = True
            # Set the current BSS signal lower so we have roam candidates
            self.rule2.enabled = True
            # Send 100 packets (to be dropped), should trigger beacon loss
            testutil.tx_packets(device.name, self.bss_hostapd[0].ifname, 100)
            device.wait_for_event('packet-loss-roam', timeout=30)
        else:
            device.roam(self.bss_hostapd[1].bssid)

        condition = 'obj.state == DeviceState.roaming'
        wd.wait_for_object_condition(device, condition)

        if pkt_loss:
            self.rule1.enabled = False
            self.rule2.enabled = False

        # Check that iwd is on BSS 1 once out of roaming state and doesn't
        # go through 'disconnected', 'autoconnect', 'connecting' in between
        from_condition = 'obj.state == DeviceState.roaming'
        to_condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_change(device, from_condition, to_condition)

        self.bss_hostapd[1].wait_for_event('AP-STA-CONNECTED %s' % device.address)

        testutil.test_iface_operstate(device.name)
        testutil.test_ifaces_connected(self.bss_hostapd[1].ifname, device.name)
        self.assertRaises(Exception, testutil.test_ifaces_connected,
                          (self.bss_hostapd[0].ifname, device.name, True, True))

        self.bss_hostapd[1].rekey(device.address)

        device.roam(self.bss_hostapd[0].bssid)

        condition = 'obj.state == DeviceState.roaming'
        wd.wait_for_object_condition(device, condition)

        # Check that iwd is on BSS 0 once out of roaming state and doesn't
        # go through 'disconnected', 'autoconnect', 'connecting' in between
        from_condition = 'obj.state == DeviceState.roaming'
        to_condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_change(device, from_condition, to_condition)

        self.bss_hostapd[0].wait_for_event('AP-STA-CONNECTED %s' % device.address)

        testutil.test_iface_operstate(device.name)
        testutil.test_ifaces_connected(self.bss_hostapd[0].ifname, device.name)
        self.assertRaises(Exception, testutil.test_ifaces_connected,
                          (self.bss_hostapd[1].ifname, device.name, True, True))

        self.bss_hostapd[0].deauthenticate(device.address)
        condition = 'obj.state == DeviceState.disconnected'
        wd.wait_for_object_condition(device, condition)

    def test_ft_psk(self):
        wd = IWD(True)

        self.bss_hostapd[0].set_value('wpa_key_mgmt', 'FT-PSK')
        self.bss_hostapd[0].set_value('ft_over_ds', '0')
        self.bss_hostapd[0].set_value('ocv', '1')
        self.bss_hostapd[0].reload()
        self.bss_hostapd[0].wait_for_event("AP-ENABLED")

        self.bss_hostapd[1].set_value('wpa_key_mgmt', 'FT-PSK')
        self.bss_hostapd[1].set_value('ft_over_ds', '0')
        self.bss_hostapd[0].set_value('ocv', '1')
        self.bss_hostapd[1].reload()
        self.bss_hostapd[1].wait_for_event("AP-ENABLED")

        self.validate_connection(wd)

    def test_ft_psk_over_ds(self):
        wd = IWD(True)

        self.bss_hostapd[0].set_value('wpa_key_mgmt', 'FT-PSK')
        self.bss_hostapd[0].set_value('ft_over_ds', '1')
        self.bss_hostapd[0].set_value('ocv', '1')
        self.bss_hostapd[0].reload()
        self.bss_hostapd[0].wait_for_event("AP-ENABLED")

        self.bss_hostapd[1].set_value('wpa_key_mgmt', 'FT-PSK')
        self.bss_hostapd[1].set_value('ft_over_ds', '1')
        self.bss_hostapd[1].set_value('ocv', '1')
        self.bss_hostapd[1].reload()
        self.bss_hostapd[1].wait_for_event("AP-ENABLED")

        self.validate_connection(wd, over_ds=True)

    def test_reassociate_psk(self):
        wd = IWD(True)

        self.bss_hostapd[0].set_value('wpa_key_mgmt', 'WPA-PSK')
        self.bss_hostapd[0].set_value('ft_over_ds', '0')
        self.bss_hostapd[0].reload()
        self.bss_hostapd[0].wait_for_event("AP-ENABLED")

        self.bss_hostapd[1].set_value('wpa_key_mgmt', 'WPA-PSK')
        self.bss_hostapd[1].set_value('ft_over_ds', '0')
        self.bss_hostapd[1].reload()
        self.bss_hostapd[1].wait_for_event("AP-ENABLED")

        self.validate_connection(wd)

    def test_roam_packet_loss(self):
        wd = IWD(True)

        self.bss_hostapd[0].set_value('wpa_key_mgmt', 'FT-PSK')
        self.bss_hostapd[0].set_value('ft_over_ds', '0')
        self.bss_hostapd[0].set_value('ocv', '1')
        self.bss_hostapd[0].reload()
        self.bss_hostapd[0].wait_for_event("AP-ENABLED")

        self.bss_hostapd[1].set_value('wpa_key_mgmt', 'FT-PSK')
        self.bss_hostapd[1].set_value('ft_over_ds', '0')
        self.bss_hostapd[0].set_value('ocv', '1')
        self.bss_hostapd[1].reload()
        self.bss_hostapd[1].wait_for_event("AP-ENABLED")

        self.validate_connection(wd, pkt_loss=True)

    def tearDown(self):
        os.system('ip link set "' + self.bss_hostapd[0].ifname + '" down')
        os.system('ip link set "' + self.bss_hostapd[1].ifname + '" down')
        os.system('ip link set "' + self.bss_hostapd[0].ifname + '" up')
        os.system('ip link set "' + self.bss_hostapd[1].ifname + '" up')

        self.rule0.enabled = False
        self.rule1.enabled = False
        self.rule2.enabled = False

    @classmethod
    def setUpClass(cls):
        hwsim = Hwsim()

        IWD.copy_to_storage('TestFT.psk')

        cls.bss_hostapd = [ HostapdCLI(config='ft-psk-ccmp-1.conf'),
                            HostapdCLI(config='ft-psk-ccmp-2.conf') ]
        rad0 = hwsim.get_radio('rad0')
        rad2 = hwsim.get_radio('rad2')

        cls.rule0 = hwsim.rules.create()
        cls.rule0.source = rad2.addresses[0]
        cls.rule0.bidirectional = True
        cls.rule0.signal = -2000
        cls.rule0.prefix = 'b0'
        cls.rule0.drop = True

        cls.rule1 = hwsim.rules.create()
        cls.rule1.source = rad2.addresses[0]
        cls.rule1.prefix = '08'
        cls.rule1.drop = True

        cls.rule2 = hwsim.rules.create()
        cls.rule2.source = rad0.addresses[0]
        cls.rule2.signal = -4000

        # Set interface addresses to those expected by hostapd config files
        os.system('ip link set dev "' + cls.bss_hostapd[0].ifname + '" down')
        os.system('ip link set dev "' + cls.bss_hostapd[0].ifname + '" addr 12:00:00:00:00:01 up')
        os.system('ip link set dev "' + cls.bss_hostapd[1].ifname + '" down')
        os.system('ip link set dev "' + cls.bss_hostapd[1].ifname + '" addr 12:00:00:00:00:02 up')

        cls.bss_hostapd[0].reload()
        cls.bss_hostapd[0].wait_for_event("AP-ENABLED")
        cls.bss_hostapd[1].reload()
        cls.bss_hostapd[1].wait_for_event("AP-ENABLED")

        # Fill in the neighbor AP tables in both BSSes.  By default each
        # instance knows only about current BSS, even inside one hostapd
        # process.
        # FT still works without the neighbor AP table but neighbor reports
        # have to be disabled in the .conf files
        cls.bss_hostapd[0].set_neighbor('12:00:00:00:00:02', 'TestFT',
                '1200000000028f0000005102060603000000')
        cls.bss_hostapd[1].set_neighbor('12:00:00:00:00:01', 'TestFT',
                '1200000000018f0000005101060603000000')

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()
        cls.bss_hostapd = None
        cls.rule0.enabled = False
        cls.rule0.remove()

if __name__ == '__main__':
    unittest.main(exit=True)
