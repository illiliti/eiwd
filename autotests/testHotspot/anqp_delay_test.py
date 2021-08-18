#!/usr/bin/python3

import unittest
import sys
import os

sys.path.append('../util')
from iwd import IWD
from iwd import IWD_CONFIG_DIR
from iwd import PSKAgent
from iwd import NetworkType
from hostapd import HostapdCLI
from hwsim import Hwsim
import testutil
from time import sleep

class Test(unittest.TestCase):

    def test_connection_success(self):
        wd = self.wd
        hapd = self.hapd
        rule0 = self.rule0

        devices = wd.list_devices(1)
        device = devices[0]
        device.autoconnect = True

        # We are dependent on a periodic scan here. We want to wait for this
        # because this is the first opportunity IWD has to do ANQP. Once ANQP
        # has been done once the network is set up and we cannot simulate the
        # 'Connect() before ANQP' race condition anymore.
        condition = 'obj.scanning'
        wd.wait_for_object_condition(device, condition)

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        # If no networks were found we likely had a quick scan. Try again to
        # allow the full autoconnect scan to happen.
        try:
            ordered_network = device.get_ordered_network('Hotspot')
        except:
            condition = 'obj.scanning'
            wd.wait_for_object_condition(device, condition)

            condition = 'not obj.scanning'
            wd.wait_for_object_condition(device, condition)

            ordered_network = device.get_ordered_network('Hotspot')

        self.assertEqual(ordered_network.type, NetworkType.eap)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        # Force the case where ANQP does not finish before Connect() comes in
        rule0.delay = 100
        rule0.prefix = '0d'

        ordered_network.network_object.connect(wait=False)

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        hapd.wait_for_event('AP-STA-CONNECTED')

        testutil.test_iface_operstate()
        testutil.test_ifaces_connected(device.name, hapd.ifname)

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

    @classmethod
    def setUpClass(cls):
        cls.hwsim = Hwsim()

        bss_radio = cls.hwsim.get_radio('rad0')
        cls.rule0 = cls.hwsim.rules.create()
        cls.rule0.source = bss_radio.addresses[0]
        cls.rule0.bidirectional = True

        cls.hapd = HostapdCLI(config='ssidHotspot.conf')

        IWD.copy_to_hotspot('example.conf')
        IWD.copy_to_storage('anqp_enabled.conf', storage_dir=IWD_CONFIG_DIR, name='main.conf')

        cls.wd = IWD(True)
        cls.psk_agent = PSKAgent('abc', ('domain\\user', 'testpasswd'))
        cls.wd.register_psk_agent(cls.psk_agent)

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

        cls.wd.unregister_psk_agent(cls.psk_agent)
        cls.psk_agent = None
        os.remove('/tmp/main.conf')

        cls.hwsim.rules.remove_all()
        cls.hwsim = None
        cls.wd = None

if __name__ == '__main__':
    unittest.main(exit=True)
