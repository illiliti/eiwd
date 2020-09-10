#! /usr/bin/python3

import unittest
import sys
import time

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import NetworkType
from hwsim import Hwsim

class TstAgent(iwd.SignalAgent):
    def handle_new_level(self, path, level):
        self.device_path = path
        self.level = level
        self.calls += 1

class Test(unittest.TestCase):
    def test_rssi_agent(self):
        rule = Hwsim().rules.create()
        rule.signal = -4000

        wd = IWD()

        device = wd.list_devices(1)[0]

        # Register agent early to catch any unexpected notifications
        agent = TstAgent()
        agent.calls = 0
        device.register_signal_agent(agent, [-20, -40, -60, -80])

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        device.scan()

        condition = 'obj.scanning'
        wd.wait_for_object_condition(device, condition)

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        ordered_network = device.get_ordered_network('TestOpen')

        self.assertEqual(ordered_network.type, NetworkType.open)
        self.assertEqual(ordered_network.signal_strength, -4000)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network.network_object.connect()

        condition = 'obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        # Test with 5 signal strength levels first, then with 3

        def test_list(rssi_pairs):
            # Roughly test big jumps in RSSI value that cross from one
            # level range to another, then with small changes that shouldn't
            # cause any notification.
            # Allow 3 secs for the agent to receive the final signal
            # strength level number and allow more than one notification
            # until it reaches the target value because the kernel (mac80211
            # at least) uses a moving-window average value over the last RSSI
            # measurements received from the driver and it changes gradually.
            # Normally 1 second is enough.
            self.assertEqual(agent.calls, 0)
            for centre, level in rssi_pairs:
                rule.signal = centre
                agent.level = -1
                condition = 'obj.level == ' + str(level)
                wd.wait_for_object_condition(agent, condition, 3)

                self.assertTrue(agent.calls > 0)
                self.assertEqual(agent.device_path, device.device_path)
                agent.calls = 0

                for offset in [-900, 500, -100, 900]:
                     rule.signal = centre - offset
                     wd.wait(0.5)

                self.assertEqual(agent.calls, 0)

        test_list([(-7000, 3), (-1000, 0), (-3000, 1), (-5000, 2),
            (-7000, 3), (-1000, 0), (-5000, 2)])
        device.unregister_signal_agent(agent)
        device.register_signal_agent(agent, [-35, -65])
        test_list([(-1500, 0), (-5000, 1), (-7500, 2), (-1500, 0)])

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        self.assertEqual(agent.calls, 0)
        device.unregister_signal_agent(agent)

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
