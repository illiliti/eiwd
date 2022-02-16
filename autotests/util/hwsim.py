#!/usr/bin/python3
import dbus
import sys
import collections

from weakref import WeakValueDictionary
from abc import ABCMeta, abstractmethod
from enum import Enum

import iwd
from config import ctx

HWSIM_SERVICE =                 'net.connman.hwsim'
HWSIM_RULE_MANAGER_INTERFACE =  'net.connman.hwsim.RuleManager'
HWSIM_RULE_INTERFACE =          'net.connman.hwsim.Rule'
HWSIM_RADIO_MANAGER_INTERFACE = 'net.connman.hwsim.RadioManager'
HWSIM_RADIO_INTERFACE =         'net.connman.hwsim.Radio'
HWSIM_INTERFACE_INTERFACE =     'net.connman.hwsim.Interface'

HWSIM_AGENT_MANAGER_PATH =      '/'

class HwsimDBusAbstract(iwd.AsyncOpAbstract):
    __metaclass__ = ABCMeta

    def __init__(self, object_path, properties = None, namespace=ctx):
        self._bus = namespace.get_bus()
        self._object_path = object_path
        proxy = self._bus.get_object(HWSIM_SERVICE, self._object_path)
        self._iface = dbus.Interface(proxy, self._iface_name)
        self._prop_proxy = dbus.Interface(proxy, iwd.DBUS_PROPERTIES)

        if properties is None:
            self._properties = self._prop_proxy.GetAll(self._iface_name)
        else:
            self._properties = properties

        self._prop_proxy.connect_to_signal("PropertiesChanged",
                self._property_changed_handler, path_keyword="path")

    def _property_changed_handler(self, interface, changed, invalidated, path):
        if interface == self._iface_name and path == self._object_path:
            for name, value in changed.items():
                self._properties[name] = value

    @abstractmethod
    def __str__(self):
        pass

    @property
    def path(self):
        return self._object_path

class Rule(HwsimDBusAbstract):
    _iface_name = HWSIM_RULE_INTERFACE

    @property
    def source(self):
        return self._properties['Source']

    @source.setter
    def source(self, value):
        self._prop_proxy.Set(self._iface_name, 'Source', value, reply_handler=self._success,
                                error_handler=self._failure)
        self._wait_for_async_op()

    @property
    def destination(self):
        return self._properties['Destination']

    @destination.setter
    def destination(self, value):
        self._prop_proxy.Set(self._iface_name, 'Destination', value, reply_handler=self._success,
                                error_handler=self._failure)
        self._wait_for_async_op()

    @property
    def bidirectional(self):
        return bool(self._properties['Bidirectional'])

    @bidirectional.setter
    def bidirectional(self, value):
        self._prop_proxy.Set(self._iface_name, 'Bidirectional',
                dbus.Boolean(value), reply_handler=self._success, error_handler=self._failure)
        self._wait_for_async_op()

    @property
    def frequency(self):
        return int(self._properties['Frequency'])

    @frequency.setter
    def frequency(self, value):
        self._prop_proxy.Set(self._iface_name, 'Frequency',
                dbus.UInt32(value), reply_handler=self._success, error_handler=self._failure)
        self._wait_for_async_op()

    @property
    def priority(self):
        return int(self._properties['Priority'])

    @priority.setter
    def priority(self, value):
        self._prop_proxy.Set(self._iface_name, 'Priority',
                dbus.Int16(value), reply_handler=self._success, error_handler=self._failure)
        self._wait_for_async_op()

    @property
    def signal(self):
        return int(self._properties['SignalStrength'])

    @signal.setter
    def signal(self, value):
        self._prop_proxy.Set(self._iface_name, 'SignalStrength',
                dbus.Int16(value), reply_handler=self._success, error_handler=self._failure)
        self._wait_for_async_op()

    @property
    def drop(self):
        return bool(self._properties['Drop'])

    @drop.setter
    def drop(self, value):
        self._prop_proxy.Set(self._iface_name, 'Drop', dbus.Boolean(value),
                                    reply_handler=self._success, error_handler=self._failure)
        self._wait_for_async_op()

    @property
    def delay(self):
        return int(self._properties['Delay'])

    @delay.setter
    def delay(self, value):
        self._prop_proxy.Set(self._iface_name, 'Delay', dbus.UInt32(value),
                            reply_handler=self._success, error_handler=self._failure)
        self._wait_for_async_op()

    @property
    def prefix(self):
        return self._properties['Prefix']

    @prefix.setter
    def prefix(self, value):
        self._prop_proxy.Set(self._iface_name, 'Prefix', dbus.ByteArray.fromhex(value),
                            reply_handler=self._success, error_handler=self._failure)
        self._wait_for_async_op()

    @property
    def enabled(self):
        return self._properties['Enabled']

    @enabled.setter
    def enabled(self, value):
        self._prop_proxy.Set(self._iface_name, 'Enabled', value,
                            reply_handler=self._success, error_handler=self._failure)
        self._wait_for_async_op()

    @property
    def match_times(self):
        return self._properties['MatchTimes']

    @match_times.setter
    def match_times(self, value):
        self._prop_proxy.Set(self._iface_name, 'MatchTimes', dbus.UInt16(value))

    @property
    def drop_ack(self):
        return self._properties(['DropAck'])

    @drop_ack.setter
    def drop_ack(self, value):
        self._prop_proxy.Set(self._iface_name, 'DropAck', value)

    @property
    def match(self):
        return self._properties['MatchBytes']

    @match.setter
    def match(self, value):
        self._prop_proxy.Set(self._iface_name, 'MatchBytes', dbus.ByteArray.fromhex(value))

    @property
    def match_offset(self):
        return self._properties(['MatchBytesOffset'])

    @match_offset.setter
    def match_offset(self, value):
        self._prop_proxy.Set(self._iface_name, 'MatchBytesOffset', dbus.UInt16(value))

    def remove(self):
        self._iface.Remove(reply_handler=self._success,
                error_handler=self._failure)

        self._wait_for_async_op()

    def __del__(self):
        self.remove()

    def __str__(self, prefix = ''):
        return prefix + 'Rule: ' + self.path + '\n' + \
               prefix + '\tSource:\t\t' + self.source + '\n' + \
               prefix + '\tDestination:\t' + self.destination + '\n' + \
               prefix + '\tBidirectional:\t' + \
               str(self.bidirectional) + '\n' + \
               prefix + '\tPriority:\t' + str(self.priority) + '\n' +\
               prefix + '\tFrequency:\t' + str(self.frequency) + '\n' + \
               prefix + '\tApply rssi:\t' + str(self.signal) + '\n' + \
               prefix + '\tApply drop:\t' + str(self.drop) + '\n' + \
               prefix + '\tPrefix:\t' + str([hex(b) for b in self.prefix]) + '\n' + \
               prefix + '\tDelay:\t' + str(self.delay) + '\n' + \
               prefix + '\tEnabled:\t' + str(self.enabled) + '\n'

class RuleSet(collections.Mapping):
    def __init__(self, hwsim, objects):
        self._dict = {}
        self._rule_manager = hwsim.rule_manager

        hwsim.object_manager.connect_to_signal("InterfacesAdded",
                self._interfaces_added_handler, HWSIM_RULE_INTERFACE)
        hwsim.object_manager.connect_to_signal("InterfacesRemoved",
                self._interfaces_removed_handler, HWSIM_RULE_INTERFACE)

        for path in objects:
            for interface in objects[path]:
                if interface == HWSIM_RULE_INTERFACE:
                    self._dict[path] = Rule(path, objects[path][interface])

    def __getitem__(self, key):
        return self._dict.__getitem__(key)

    def __iter__(self):
        return self._dict.__iter__()

    def __len__(self):
        return self._dict.__len__()

    def __delitem__(self, key):
        self._dict.pop(key).remove()

    def _interfaces_added_handler(self, path, interfaces):
        self._dict[path] = Rule(interfaces[HWSIM_RULE_INTERFACE])

    def _interfaces_removed_handler(self, path, interfaces):
        del _dict[path]

    def create(self):
        path = self._rule_manager.AddRule()
        obj = Rule(path)
        self._dict[path] = obj
        return obj

    def remove_all(self):
        for rule in self._dict.values():
            rule.remove()

class Radio(HwsimDBusAbstract):
    _iface_name = HWSIM_RADIO_INTERFACE

    @property
    def name(self):
        return self._properties['Name']

    @property
    def addresses(self):
        return [str(addr) for addr in self._properties['Addresses']]

    def remove(self):
        self._iface.Destroy(reply_handler=self._success,
                error_handler=self._failure)

        self._wait_for_async_op()

    def __str__(self, prefix = ''):
        return prefix + 'Radio: ' + self.path + '\n' + \
               prefix + '\tName:\t\t' + self.name + '\n' + \
               prefix + '\tAddresses:\t' + repr(self.destination) + '\n'

class RadioList(collections.Mapping):
    def __init__(self, hwsim, objects):
        self._dict = {}
        self._radio_manager = hwsim.radio_manager

        hwsim.object_manager.connect_to_signal("InterfacesAdded",
                self._interfaces_added_handler, HWSIM_RADIO_INTERFACE)
        hwsim.object_manager.connect_to_signal("InterfacesRemoved",
                self._interfaces_removed_handler, HWSIM_RADIO_INTERFACE)

        for path in objects:
            for interface in objects[path]:
                if interface == HWSIM_RADIO_INTERFACE:
                    self._dict[path] = Radio(path, objects[path][interface])

    def __getitem__(self, key):
        return self._dict.__getitem__(key)

    def __iter__(self):
        return self._dict.__iter__()

    def __len__(self):
        return self._dict.__len__()

    def __delitem__(self, key):
        self._dict.pop(key).remove()

    def values(self):
        return self._dict.values()

    def _interfaces_added_handler(self, path, interfaces):
        self._dict[path] = Radio(interfaces[HWSIM_RADIO_INTERFACE])

    def _interfaces_removed_handler(self, path, interfaces):
        del _dict[path]

    def create(self, name, p2p_device=False, iftype_disable=None,
                cipher_disable=None, wait=True):
        args = dbus.Dictionary({
            'Name': name,
            'P2P': p2p_device,
        }, signature='sv')

        if iftype_disable:
            args['InterfaceTypeDisable'] = iftype_disable

        if cipher_disable:
            args['CipherTypeDisable'] = cipher_disable

        if not wait:
            self._radio_manager.CreateRadio(args, reply_handler=self._success,
                                                error_handler=self._failure)
            return None

        path = self._radio_manager.CreateRadio(args)
        obj = Radio(path)
        self._dict[path] = obj
        return obj

    def _success(self, bla):
        pass

    def _failure(self, ex):
        pass

class Hwsim(iwd.AsyncOpAbstract):
    _instances = WeakValueDictionary()

    def __new__(cls, namespace=ctx):
        key = id(namespace)

        if key not in cls._instances.keys():
            obj = object.__new__(cls)
            obj._initialized = False

            cls._instances[key] = obj

        return cls._instances[key]

    def __init__(self, namespace=ctx):
        if self._initialized:
            return

        self._initialized = True

        self._bus = namespace.get_bus()

        self._rule_manager_if = dbus.Interface(
                self._bus.get_object(HWSIM_SERVICE, '/'),
                HWSIM_RULE_MANAGER_INTERFACE)
        self._radio_manager_if = dbus.Interface(
                self._bus.get_object(HWSIM_SERVICE, '/'),
                HWSIM_RADIO_MANAGER_INTERFACE)
        self._object_manager_if = dbus.Interface(
                self._bus.get_object(HWSIM_SERVICE, '/'),
                iwd.DBUS_OBJECT_MANAGER)

        objects = self.object_manager.GetManagedObjects()

        self._rules = RuleSet(self, objects)
        self._radios = RadioList(self, objects)

    @property
    def rules(self):
        return self._rules

    @property
    def rule_manager(self):
        return self._rule_manager_if

    @property
    def radios(self):
        return self._radios

    @property
    def radio_manager(self):
        return self._radio_manager_if

    @property
    def object_manager(self):
        return self._object_manager_if

    @staticmethod
    def _convert_address(address):
        first = int(address[0:2], base=16)
        first |= 0x40
        first = format(first, 'x')

        address = first + address[2:]

        return address

    def spoof_disassociate(self, radio, freq, station):
        '''
            Send a spoofed disassociate frame to a station
        '''
        dest = self._convert_address(radio.addresses[0].replace(':', ''))

        frame = 'a0 00 3a 01'
        frame += station.replace(':', '')
        frame += dest
        frame += dest
        frame += '30 01 07 00'
        self.spoof_frame(radio, freq, station, frame)

    def spoof_frame(self, radio, freq, station, frame):
        '''
            Send a spoofed arbitrary frame to a station
        '''
        radio_path = None
        objects = self.object_manager.GetManagedObjects()

        for path in objects:
            obj = objects[path]
            for interface in obj:
                if interface == HWSIM_INTERFACE_INTERFACE:
                    if obj[interface]['Address'] == radio.addresses[0] or \
                                    obj[interface]['Address'] == radio.addresses[1]:
                        radio_path = path
                        break

        if not radio_path:
            raise Exception("Could not find radio %s" % radio.path)

        iface = dbus.Interface(self._bus.get_object(HWSIM_SERVICE, radio_path),
                HWSIM_INTERFACE_INTERFACE)

        iface.SendFrame(dbus.ByteArray.fromhex(station.replace(':', '')),
                        freq, -30, dbus.ByteArray.fromhex(frame))

    def get_radio(self, name):
        for path in self.radios:
            radio = self.radios[path]
            if radio.name == name:
                return radio

        return None
