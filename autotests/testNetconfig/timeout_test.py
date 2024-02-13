import unittest
import sys
import os

sys.path.append('../util')
from iwd import IWD
from iwd import PSKAgent
from iwd import NetworkType

class Test(unittest.TestCase):

    def test_netconfig_timeout(self):
        IWD.copy_to_storage('autoconnect.psk', name='ap-ns1.psk')

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

        condition = 'obj.state == DeviceState.connecting'
        wd.wait_for_object_condition(device, condition)

        device.wait_for_event("connecting (netconfig)")

        # Netconfig should fail, and IWD should disconnect
        from_condition = 'obj.state == DeviceState.connecting'
        to_condition = 'obj.state == DeviceState.disconnecting'
        wd.wait_for_object_change(device, from_condition, to_condition, max_wait=60)

        # Autoconnect should then try again
        condition = 'obj.state == DeviceState.connecting'
        wd.wait_for_object_condition(device, condition)

        device.wait_for_event("connecting (netconfig)")

        device.disconnect()
        condition = 'obj.state == DeviceState.disconnected'
        wd.wait_for_object_condition(device, condition)

    @classmethod
    def setUpClass(cls):
        cls.orig_path = os.environ['PATH']
        os.environ['PATH'] = '/tmp/test-bin:' + os.environ['PATH']
        IWD.copy_to_storage('resolvconf', '/tmp/test-bin')

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()
        os.system('rm -rf /tmp/radvd.conf /tmp/resolvconf.log /tmp/test-bin')
        os.environ['PATH'] = cls.orig_path

if __name__ == '__main__':
    unittest.main(exit=True)
