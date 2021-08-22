#!/usr/bin/python3

from typing import Iterable
import unittest
import sys

sys.path.append('../util')
from iwd import IWD
from iwd import NetworkType
from iwd import PSKAgent
from hlrauc import AuthCenter
from ofono import Ofono
from config import ctx
import testutil
import traceback

class Test(unittest.TestCase):
    def copy_network(self, name):
        IWD.copy_to_storage(name, name='ssidEAP.8021x')
        self.wd.wait_for_object_condition(self.wd,
                                    '"ssidEAP" in [n.name for n in obj.list_known_networks()]')

    def remove_network(self):
        networks = self.wd.list_known_networks()
        [n.forget() for n in networks if n.name == 'ssidEAP']
        self.wd.wait_for_object_condition(self.wd,
                                    '"ssidEAP" not in [n.name for n in obj.list_known_networks()]')

    def validate_connection(self, wd, *secrets):
        if secrets:
            psk_agent = PSKAgent(*secrets)
            wd.register_psk_agent(psk_agent)

        devices = wd.list_devices(1)
        self.assertIsNotNone(devices)
        device = devices[0]

        ordered_network = device.get_ordered_network('ssidEAP')

        self.assertEqual(ordered_network.type, NetworkType.eap)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network.network_object.connect()

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        testutil.test_iface_operstate()
        testutil.test_ifaces_connected()

        if secrets:
            wd.unregister_psk_agent(psk_agent)

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

    #
    # EAP-AKA
    #
    def test_eap_aka(self):
        if not ctx.is_process_running('ofonod'):
            self.skipTest("ofono not running")

        ofono = Ofono()
        ofono.enable_modem('/phonesim')
        ofono.wait_for_sim_auth()

        auth = AuthCenter('/tmp/hlrauc.sock', '/tmp/sim/aka.db')

        self.copy_network('sim/ssidEAP-AKA.8021x')

        try:
            self.validate_connection(self.wd)
        finally:
            auth.stop()

    #
    # EAP-AKA'
    #
    def test_eap_aka_prime(self):
        if not ctx.is_process_running('ofonod'):
            self.skipTest("ofono not running")

        ofono = Ofono()
        ofono.enable_modem('/phonesim')
        ofono.wait_for_sim_auth()

        auth = AuthCenter('/tmp/hlrauc.sock', '/tmp/sim/aka.db')

        self.copy_network('sim/ssidEAP-AKA-prime.8021x')

        try:
            self.validate_connection(self.wd)
        finally:
            auth.stop()

    #
    # EAP-SIM
    #
    def test_eap_sim(self):
        if not ctx.is_process_running('ofonod'):
            self.skipTest("ofono not running")

        ofono = Ofono()
        ofono.enable_modem('/phonesim')
        ofono.wait_for_sim_auth()

        auth = AuthCenter('/tmp/hlrauc.sock', '/tmp/sim/sim.db')

        self.copy_network('sim/ssidEAP-SIM.8021x')

        try:
            self.validate_connection(self.wd)
        finally:
            auth.stop()

    #
    # EAP-MSCHAPv2
    #
    # * Credentials in 8021x file
    # * Password-Hash in 8021x file
    # * Agent request for password
    # * Agent request for user + password
    #
    def test_eap_mschapv2(self):
        self.copy_network('mschapv2/ssidEAP-MSCHAPV2.8021x')
        self.validate_connection(self.wd)

        self.copy_network('mschapv2/ssidEAP-MSCHAPV2-hash.8021x')
        self.validate_connection(self.wd)

        self.copy_network('mschapv2/ssidEAP-MSCHAPV2-nopass.8021x')
        self.validate_connection(self.wd, [], ('mschapv2@example.com', 'Password'))

        self.copy_network('mschapv2/ssidEAP-MSCHAPV2-nouserpass.8021x')
        self.validate_connection(self.wd, [], ('mschapv2@example.com', 'Password'))

    #
    # EAP-PEAP
    #
    # * Test all combinations of PEAP, PEAPv0, PEAPv1 with MD5, GTC, MSCHAPv2
    #
    def test_eap_peap(self):
        for ver in ['PEAP', 'PEAPv0', 'PEAPv1']:
            for inner in ['MD5', 'GTC', 'MSCHAPv2']:
                self.copy_network('peap/ssidEAP-%s-%s.8021x' % (ver, inner))

                try:
                    self.validate_connection(self.wd)
                except Exception as e:
                    # Catch an error here and print the actual PEAP combo that failed
                    traceback.print_exc()
                    raise Exception("%s-%s test failed" % (ver, inner))

                self.remove_network()

    #
    # EAP-PEAP + SIM
    #
    # * Tests EAP-PEAP + SIM separately to allow skipping if ofono is not found
    #
    def test_eap_peap_sim(self):
        if not ctx.is_process_running('ofonod'):
            self.skipTest("ofono not running")

        ofono = Ofono()
        ofono.enable_modem('/phonesim')
        ofono.wait_for_sim_auth()

        auth = AuthCenter('/tmp/hlrauc.sock', '/tmp/sim/sim.db')

        for ver in ['PEAP', 'PEAPv0', 'PEAPv1']:
                self.copy_network('peap/ssidEAP-%s-SIM.8021x' % ver)

                try:
                    self.validate_connection(self.wd)
                except Exception as e:
                    # Catch an error here and print the actual PEAP combo that failed
                    traceback.print_exc()
                    auth.stop()
                    raise Exception("%s-SIM test failed" % ver)

                self.remove_network()

        auth.stop()

    #
    # EAP-PWD
    #
    def test_eap_pwd(self):
        self.copy_network('ssidEAP-PWD.8021x')

        self.validate_connection(self.wd)

    #
    # EAP-TLS
    #
    # * Encrypted private key, passphrase in 8021x file
    # * Unencrypted private key
    # * Encrypted private key, passphrase provided by agent
    # * Embedded PEM inside 8021x file
    # * KeyBundle
    #
    def test_eap_tls(self):
        for name, secrets in [('keypass', None), ('nokeypass', None),
                        ('des-ede3', 'abc'), ('embedded', None), ('keybundle', None)]:
            self.copy_network('tls/ssidEAP-TLS-%s.8021x' % name)
            try:
                self.validate_connection(self.wd, secrets)
            except Exception as e:
                traceback.print_exc()
                raise Exception('EAP-TLS (%s) failed' % name)

            self.remove_network()

    #
    # EAP-TTLS
    #
    # * CHAP, MD5, MSCHAPV2 as phase 2
    # * Tunneled-MSCHAP, Tunneled-MSCHAPV2, Tunneled-PAP as phase 2
    #
    def test_eap_ttls(self):
        for name, secrets in [('CHAP', ('ttls@example.com', ('ttls-chap-phase2@example.com', 'Password'))),
                              ('MD5', None),
                              ('MSCHAPV2', ('ttls@example.com', ('mschapv2-phase2@example.com', 'Password'))),
                              ('Tunneled-MSCHAP', ('ttls@example.com', ('ttls-mschap-phase2@example.com', 'Password'))),
                              ('Tunneled-MSCHAPV2', ('ttls@example.com', ('ttls-mschapv2-phase2@example.com', 'Password'))),
                              ('Tunneled-PAP', ('ttls@example.com', ('ttls-pap-phase2@example.com', 'Password')))]:
            self.copy_network('ttls/ssidEAP-TTLS-%s.8021x' % name)
            try:
                if isinstance(secrets, Iterable):
                    self.validate_connection(self.wd, *secrets)
                else:
                    self.validate_connection(self.wd, None)
            except Exception as e:
                    traceback.print_exc()
                    raise Exception('EAP-TTLS (%s) failed' % name)

            self.remove_network()

    def setUp(self):
        IWD.clear_storage()

    def tearDown(self):
        self.remove_network()

    @classmethod
    def setUpClass(cls):
        cls.wd = IWD()

    @classmethod
    def tearDownClass(cls):
        cls.wd = None
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
