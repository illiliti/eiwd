#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
import os
from iwd import IWD
from iwd import NetworkType
from iwd import PSKAgent

class Test(unittest.TestCase):
    def profile_is_encrypted(self, profile):
        with open('/tmp/iwd/' + profile) as f:
            contents = f.read()

        if 'Passphrase' in contents:
            return False

        return True

    def validate(self, wd):
        devices = wd.list_devices(1)
        device = devices[0]

        ordered_network = device.get_ordered_network('ssidCCMP')

        self.assertEqual(ordered_network.type, NetworkType.psk)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network.network_object.connect()

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

    # Tests that an existing plaintext profile gets encrypted
    def test_new_profile(self):
        IWD.copy_to_storage('ssidCCMP.psk')

        mtime = os.path.getmtime('/tmp/iwd/' + 'ssidCCMP.psk')
        self.assertFalse(self.profile_is_encrypted('ssidCCMP.psk'))

        wd = IWD(True)

        # Make sure profile was accepted
        condition = 'len(obj.list_known_networks()) == 1'
        wd.wait_for_object_condition(wd, condition)

        # Check the file was modified (should be encrypted now)
        self.assertNotEqual(mtime, os.path.getmtime('/tmp/iwd/' + 'ssidCCMP.psk'))

        self.validate(wd)

        self.assertTrue(self.profile_is_encrypted('ssidCCMP.psk'))

    # Tests that a new connection with agent gets written to an encrypted profile
    def test_agent_profile(self):
        wd = IWD(True)

        psk_agent = PSKAgent("secret123")
        wd.register_psk_agent(psk_agent)

        with self.assertRaises(FileNotFoundError):
            self.profile_is_encrypted('ssidCCMP.psk')

        self.validate(wd)

        self.assertTrue(self.profile_is_encrypted('ssidCCMP.psk'))

        wd.unregister_psk_agent(psk_agent)

    # Tests that an invalid profile gets re-written after an agent request
    def test_invalid_profile_rewritten(self):
        bad_config = '[Security]\nPassphrase=incorrect\n'
        os.system('echo "%s" > /tmp/iwd/ssidCCMP.psk' % bad_config)

        wd = IWD(True)

        condition = 'len(obj.list_known_networks()) == 1'
        wd.wait_for_object_condition(wd, condition)

        # IWD should still encrypt the profile automatically
        self.assertTrue(self.profile_is_encrypted('ssidCCMP.psk'))

        # This should fail
        with self.assertRaises(iwd.FailedEx):
            self.validate(wd)

        psk_agent = PSKAgent("secret123")
        wd.register_psk_agent(psk_agent)

        self.validate(wd)

        self.assertTrue(self.profile_is_encrypted('ssidCCMP.psk'))

    # Tests that a profile that doesn't decrypt wont become a known network
    def test_decryption_failure(self):
        bad_config = \
'''
[Security]
EncryptedSalt=000102030405060708090a0b0c0d0e0f
EncryptedSecurity=aabbccddeeff00112233445566778899
'''
        os.system('echo "%s" > /tmp/iwd/ssidCCMP.psk' % bad_config)

        wd = IWD(True)

        self.assertEqual(wd.list_known_networks(), [])

        # This test starts and stops IWD so quickly the DBus utilities don't
        # even have a chance to set up the Device interface object which causes
        # exceptions on the next test as the InterfaceAdded signals arrive. This
        # allows the device interface to get set up before ending the test.
        wd.list_devices(1)

    def test_runtime_profile(self):
        wd = IWD(True)

        self.assertEqual(wd.list_known_networks(), [])

        # Add profile after IWD starts
        IWD.copy_to_storage('ssidCCMP.psk')

        self.validate(wd)

        # Should now be encrypted
        self.assertTrue(self.profile_is_encrypted('ssidCCMP.psk'))

        with open('/tmp/iwd/ssidCCMP.psk') as f:
            profile = f.read()

        # Edit the profile, corrupting it
        profile.replace('EncryptedSecurity=', 'EncryptedSecurity=00')

        devices = wd.list_devices(1)
        device = devices[0]
        condition = 'obj.state == DeviceState.disconnected'
        wd.wait_for_object_condition(device, condition)

    def tearDown(self):
        IWD.clear_storage()

    @classmethod
    def setUpClass(cls):
        os.environ['CREDENTIALS_DIRECTORY'] = '/tmp'

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
