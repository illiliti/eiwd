#!/usr/bin/python3

import unittest
import sys
import os

sys.path.append('../util')
from iwd import IWD_CONFIG_DIR
from iwd import IWD
from iwd import PSKAgent
from iwd import NetworkType
from hwsim import Hwsim
from hostapd import HostapdCLI
import testutil

class Test(unittest.TestCase):
    def validate(self, wd, resend_m3=False):
        hapd = HostapdCLI('ssidCCMP.conf')

        psk_agent = PSKAgent("secret123")
        wd.register_psk_agent(psk_agent)

        devices = wd.list_devices(1)
        device = devices[0]

        ordered_network = device.get_ordered_network('ssidCCMP')

        self.assertEqual(ordered_network.type, NetworkType.psk)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network.network_object.connect()

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        testutil.test_iface_operstate()
        testutil.test_ifaces_connected()


        # Rekey 5 times just to make sure the key ID can be toggled back and
        # forth without causing problems.
        for i in range(5):
            hapd.rekey(device.address)

            if resend_m3:
                hapd.resend_m3(device.address)

            testutil.test_iface_operstate()
            testutil.test_ifaces_connected()

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        wd.unregister_psk_agent(psk_agent)

    def test_ext_key_control_port(self):
        self.hapd.set_value('extended_key_id', '1')
        self.hapd.reload()

        self.wd = IWD(True)

        self.validate(self.wd)

    def test_ext_key_control_port_retransmit(self):
        self.hapd.set_value('extended_key_id', '1')
        self.hapd.reload()

        self.wd = IWD(True)

        self.validate(self.wd, resend_m3=True)

    def test_ext_key_index_1(self):
        self.hapd.set_value('extended_key_id', '2')
        self.hapd.reload()

        self.wd = IWD(True)

        self.validate(self.wd)

    def test_ext_key_pae(self):
        self.hapd.set_value('extended_key_id', '1')
        self.hapd.reload()

        IWD.copy_to_storage('main_pae.conf', storage_dir=IWD_CONFIG_DIR, name='main.conf')

        self.wd = IWD(True)

        self.validate(self.wd)

    def tearDown(self):
        try:
            os.system('rm -rf %s/main.conf' % IWD_CONFIG_DIR)
        except:
            pass

        self.wd = None

    @classmethod
    def setUpClass(cls):
        cls.hapd = HostapdCLI()

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()
        cls.hapd = None

if __name__ == '__main__':
    unittest.main(exit=True)
