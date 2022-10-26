#!/usr/bin/python3
from gi.repository import GLib

import dbus
import dbus.service
import dbus.mainloop.glib
import sys
import os
import threading
import time
import collections.abc
import datetime
import weakref

from collections.abc import Mapping
from abc import ABCMeta, abstractmethod
from enum import Enum

from config import ctx

IWD_STORAGE_DIR =               '/tmp/iwd'
IWD_CONFIG_DIR =                '/tmp'

DBUS_OBJECT_MANAGER =           'org.freedesktop.DBus.ObjectManager'
DBUS_PROPERTIES =               'org.freedesktop.DBus.Properties'

IWD_SERVICE =                   'net.connman.iwd'
IWD_WIPHY_INTERFACE =           'net.connman.iwd.Adapter'
IWD_AGENT_INTERFACE =           'net.connman.iwd.Agent'
IWD_AGENT_MANAGER_INTERFACE =   'net.connman.iwd.AgentManager'
IWD_DEVICE_INTERFACE =          'net.connman.iwd.Device'
IWD_KNOWN_NETWORK_INTERFACE =   'net.connman.iwd.KnownNetwork'
IWD_NETWORK_INTERFACE =         'net.connman.iwd.Network'
IWD_WSC_INTERFACE =             'net.connman.iwd.SimpleConfiguration'
IWD_SIGNAL_AGENT_INTERFACE =    'net.connman.iwd.SignalLevelAgent'
IWD_AP_INTERFACE =              'net.connman.iwd.AccessPoint'
IWD_ADHOC_INTERFACE =           'net.connman.iwd.AdHoc'
IWD_STATION_INTERFACE =         'net.connman.iwd.Station'
IWD_P2P_INTERFACE =             'net.connman.iwd.p2p.Device'
IWD_P2P_PEER_INTERFACE =        'net.connman.iwd.p2p.Peer'
IWD_P2P_SERVICE_MANAGER_INTERFACE = 'net.connman.iwd.p2p.ServiceManager'
IWD_P2P_WFD_INTERFACE =         'net.connman.iwd.p2p.Display'
IWD_STATION_DEBUG_INTERFACE =   'net.connman.iwd.StationDebug'
IWD_DPP_INTERFACE =             'net.connman.iwd.DeviceProvisioning'

IWD_AGENT_MANAGER_PATH =        '/net/connman/iwd'
IWD_TOP_LEVEL_PATH =            '/'

class UnknownDBusEx(Exception): pass
class InProgressEx(dbus.DBusException): pass
class FailedEx(dbus.DBusException): pass
class AbortedEx(dbus.DBusException): pass
class NotAvailableEx(dbus.DBusException): pass
class InvalidArgumentsEx(dbus.DBusException): pass
class InvalidFormatEx(dbus.DBusException): pass
class AlreadyExistsEx(dbus.DBusException): pass
class NotFoundEx(dbus.DBusException): pass
class NotSupportedEx(dbus.DBusException): pass
class NoAgentEx(dbus.DBusException): pass
class NotConnectedEx(dbus.DBusException): pass
class NotConfiguredEx(dbus.DBusException): pass
class NotImplementedEx(dbus.DBusException): pass
class ServiceSetOverlapEx(dbus.DBusException): pass
class AlreadyProvisionedEx(dbus.DBusException): pass
class NotHiddenEx(dbus.DBusException): pass
class CanceledEx(dbus.DBusException):
    _dbus_error_name = 'net.connman.iwd.Error.Canceled'


_dbus_ex_to_py = {
    'Canceled' :            CanceledEx,
    'InProgress' :          InProgressEx,
    'Failed' :              FailedEx,
    'Aborted' :             AbortedEx,
    'NotAvailable' :        NotAvailableEx,
    'InvalidArguments' :    InvalidArgumentsEx,
    'InvalidFormat' :       InvalidFormatEx,
    'AlreadyExists' :       AlreadyExistsEx,
    'NotFound' :            NotFoundEx,
    'NotSupported' :        NotSupportedEx,
    'NoAgent' :             NoAgentEx,
    'NotConnected' :        NotConnectedEx,
    'NotConfigured' :       NotConfiguredEx,
    'NotImplemented' :      NotImplementedEx,
    'ServiceSetOverlap' :   ServiceSetOverlapEx,
    'AlreadyProvisioned' :  AlreadyProvisionedEx,
    'NotHidden' :           NotHiddenEx,
}


def _convert_dbus_ex(dbus_ex):
    ex_name = dbus_ex.get_dbus_name()
    ex_short_name = ex_name[ex_name.rfind(".") + 1:]
    if ex_short_name in _dbus_ex_to_py:
        return _dbus_ex_to_py[ex_short_name](dbus_ex)
    else:
        return UnknownDBusEx(ex_name + ': ' + dbus_ex.get_dbus_message())


class AsyncOpAbstract(object):
    __metaclass__ = ABCMeta

    _is_completed = False
    _exception = None

    def _success(self):
        self._is_completed = True

    def _failure(self, ex):
        self._is_completed = True
        self._exception = _convert_dbus_ex(ex)

    def _wait_for_async_op(self):
        ctx.non_block_wait(lambda s: s._is_completed, 30, self, exception=None)

        self._is_completed = False
        if self._exception is not None:
            tmp = self._exception
            self._exception = None
            raise tmp


class IWDDBusAbstract(AsyncOpAbstract):
    __metaclass__ = ABCMeta

    def __init__(self, object_path = None, properties = None, service=IWD_SERVICE, namespace=ctx):
        self._bus = namespace.get_bus()
        self._namespace = namespace

        self._object_path = object_path
        proxy = self._bus.get_object(service, self._object_path)
        self._iface = dbus.Interface(proxy, self._iface_name)
        self._prop_proxy = dbus.Interface(proxy, DBUS_PROPERTIES)

        if properties is None:
            self._properties = self._prop_proxy.GetAll(self._iface_name)
        else:
            self._properties = properties

        self._prop_proxy.connect_to_signal("PropertiesChanged",
                                           self._property_changed_handler,
                                           DBUS_PROPERTIES,
                                           path_keyword="path")

    def _property_changed_handler(self, interface, changed, invalidated, path):
        if interface == self._iface_name and path == self._object_path:
            for name, value in changed.items():
                self._properties[name] = value

    @abstractmethod
    def __str__(self):
        pass


class DeviceState(Enum):
    '''Conection state of a device'''
    connected =     'connected'
    disconnected =  'disconnected'
    connecting =    'connecting'
    disconnecting = 'disconnecting'
    roaming =       'roaming'

    def __str__(self):
        return self.value

    @classmethod
    def from_str(cls, string):
        return getattr(cls, string, None)


class NetworkType(Enum):
    '''Network security type'''
    open =  'open'
    psk =   'psk'
    eap =   '8021x'
    hotspot = 'hotspot'

    def __str__(self):
        return str(self.value)

    @classmethod
    def from_string(cls, string):
        type = None
        for attr in dir(cls):
            if (str(getattr(cls, attr)) == string):
                type = getattr(cls, attr)
                break
        return type


class SignalAgent(dbus.service.Object):
    def __init__(self, passphrase = None):
        self._path = '/test/agent/' + str(int(round(time.time() * 1000)))

        dbus.service.Object.__init__(self, ctx.get_bus(), self._path)

    @property
    def path(self):
        return self._path

    @dbus.service.method(IWD_SIGNAL_AGENT_INTERFACE,
                         in_signature='', out_signature='')
    def Release(self):
        print("SignalAgent released")

    @dbus.service.method(IWD_SIGNAL_AGENT_INTERFACE,
                         in_signature='oy', out_signature='')
    def Changed(self, path, level):
        self.handle_new_level(str(path), int(level))

    @abstractmethod
    def handle_new_level(self, path, level):
        pass

class AdHocDevice(IWDDBusAbstract):
    '''
        Class represents an AdHoc device object: net.connman.iwd.AdHoc
    '''
    _iface_name = IWD_ADHOC_INTERFACE

    @property
    def started(self):
        return self._properties['Started']

    @property
    def connected_peers(self):
        return self._properties['ConnectedPeers']

class StationDebug(IWDDBusAbstract):
    '''
        Class represents net.connman.iwd.StationDebug
    '''
    _iface_name = IWD_STATION_DEBUG_INTERFACE

    def __init__(self, *args, **kwargs):
        self._events = []

        IWDDBusAbstract.__init__(self, *args, **kwargs)

        self._iface.connect_to_signal("Event", self._event_handler)

    def _event_handler(self, event, data):
        self._events.insert(0, (event, data))

    @property
    def autoconnect(self):
        return self._properties['AutoConnect']

    def connect_bssid(self, address):
        self._iface.ConnectBssid(dbus.ByteArray.fromhex(address.replace(':', '')))

    def roam(self, address):
        self._iface.Roam(dbus.ByteArray.fromhex(address.replace(':', '')))

    def scan(self, frequencies):
        frequencies = dbus.Array([dbus.UInt16(f) for f in frequencies])
        self._iface.Scan(frequencies)

    def _poll_event(self, event):
        for idx, e in enumerate(self._events):
            if event == e[0]:
                # Consume any older events
                self._events = self._events[:idx]
                return True

        return False

    def wait_for_event(self, event, timeout=10):
        return ctx.non_block_wait(self._poll_event, timeout, event,
                                    exception=TimeoutError("waiting for event"))

class DeviceProvisioning(IWDDBusAbstract):
    '''
        Class represents net.connman.iwd.DeviceProvisioning
    '''
    _iface_name = IWD_DPP_INTERFACE

    def start_enrollee(self):
        return self._iface.StartEnrollee()

    def start_configurator(self, uri=None):
        if uri:
            return self._iface.ConfigureEnrollee(uri)
        else:
            return self._iface.StartConfigurator()

    def stop(self):
        self._iface.Stop()

    @property
    def uri(self):
        return self._properties['URI']

    @property
    def started(self):
        return self._properties['Started']

    @property
    def role(self):
        return self._properties['Role']

class Device(IWDDBusAbstract):
    '''
        Class represents a network device object: net.connman.iwd.Device
        with its properties and methods
    '''
    _iface_name = IWD_DEVICE_INTERFACE

    def __init__(self, *args, **kwargs):
        self._wps_manager_if = None
        self._station_if = None
        self._station_props = None
        self._station_debug_obj = None
        self._dpp_obj = None

        IWDDBusAbstract.__init__(self, *args, **kwargs)

    @property
    def _wps_manager(self):
        if self._wps_manager_if is None:
            _wps_manager_if =\
                dbus.Interface(self._bus.get_object(IWD_SERVICE,
                                                    self.device_path),
                               IWD_WSC_INTERFACE)
        return _wps_manager_if

    @property
    def _station(self):
        if self._station_if is None:
            self._station_if = dbus.Interface(self._bus.get_object(IWD_SERVICE,
                                                            self.device_path),
                                            IWD_STATION_INTERFACE)
        return self._station_if

    @property
    def _device_provisioning(self):
        if self._properties['Mode'] != 'station':
            self._prop_proxy.Set(IWD_DEVICE_INTERFACE, 'Mode', 'station')

        if self._dpp_obj is None:
            self._dpp_obj = DeviceProvisioning(object_path=self._object_path,
                                                namespace=self._namespace)

        return self._dpp_obj

    @property
    def _station_debug(self):
        if self._properties['Mode'] != 'station':
            self._prop_proxy.Set(IWD_DEVICE_INTERFACE, 'Mode', 'station')

        if self._station_debug_obj is None:
            self._station_debug_obj = StationDebug(object_path=self._object_path,
                                                    namespace=self._namespace)

        return self._station_debug_obj

    def _station_properties(self):
        if self._station_props is not None:
            return self._station_props

        if self._properties['Mode'] != 'station':
            self._prop_proxy.Set(IWD_DEVICE_INTERFACE, 'Mode', 'station')

        self._station_prop_if = \
                dbus.Interface(self._bus.get_object(IWD_SERVICE,
                                                            self.device_path),
                                                DBUS_PROPERTIES)

        self._station_props = self._station_prop_if.GetAll(IWD_STATION_INTERFACE)

        self._station_prop_if.connect_to_signal("PropertiesChanged",
                                        self.__station_property_changed_handler,
                                        DBUS_PROPERTIES, path_keyword="path")

        return self._station_props

    def __station_property_changed_handler(self, interface, changed,
                                                            invalidated, path):
        if interface == IWD_STATION_INTERFACE and path == self._object_path:
            for name, value in changed.items():
                self._station_props[name] = value

                if name == 'Mode' and value != 'station':
                    self._station_debug_obj = None

    @property
    def device_path(self):
        '''
            Device's dbus path.

            @rtype: string
        '''
        return self._object_path

    @property
    def name(self):
        '''
            Device's interface name.

            @rtype: string
        '''
        return self._properties['Name']

    @property
    def address(self):
        '''
            Interface's hardware address in the XX:XX:XX:XX:XX:XX format.

            @rtype: string
        '''
        return self._properties['Address']

    @property
    def state(self):
        '''
            Reflects the general network connection state.

            @rtype: object (State)
        '''
        props = self._station_properties()
        return DeviceState.from_str(props['State'])

    @property
    def connected_network(self):
        '''
            net.connman.iwd.Network object representing the
            network the device is currently connected to or to
            which a connection is in progress.

            @rtype: object (Network)
        '''
        props = self._station_properties()
        return props.get('ConnectedNetwork')

    @property
    def powered(self):
        '''
            True if the interface is UP. If false, the device's radio is
            powered down and no other actions can be performed on the device.

            @rtype: boolean
        '''
        return bool(self._properties['Powered'])

    @property
    def scanning(self):
        '''
        Reflects whether the device is currently scanning
        for networks.  net.connman.iwd.Network objects are
        updated when this property goes from true to false.

        @rtype: boolean
        '''
        props = self._station_properties()
        return bool(props['Scanning'])

    @property
    def autoconnect(self):
        return self._station_debug.autoconnect

    @autoconnect.setter
    def autoconnect(self, value):
        self._station_debug._prop_proxy.Set(IWD_STATION_DEBUG_INTERFACE,
                                            'AutoConnect', value)

    def scan(self, wait=True):
        '''Schedule a network scan.

           Possible exception: BusyEx
                               FailedEx
        '''
        self._iface.Scan(dbus_interface=IWD_STATION_INTERFACE,
                               reply_handler=self._success,
                               error_handler=self._failure)

        if wait:
            self._wait_for_async_op()

    def disconnect(self):
        '''Disconnect from the network

           Possible exception: BusyEx
                               FailedEx
                               NotConnectedEx
        '''
        self._iface.Disconnect(dbus_interface=IWD_STATION_INTERFACE,
                               reply_handler=self._success,
                               error_handler=self._failure)

        self._wait_for_async_op()

    def get_ordered_networks(self, scan_if_needed = True, full_scan = False, list = []):
        '''Return the list of networks found in the most recent
           scan, sorted by their user interface importance
           score as calculated by iwd.  If the device is
           currently connected to a network, that network is
           always first on the list, followed by any known
           networks that have been used at least once before,
           followed by any other known networks and any other
           detected networks as the last group.  Within these
           groups the maximum relative signal-strength is the
           main sorting factor.
        '''
        ordered_networks = []
        if not full_scan:
            for bus_obj in self._station.GetOrderedNetworks():
                ordered_network = OrderedNetwork(bus_obj, self._bus, self._namespace)
                ordered_networks.append(ordered_network)

            names = [x.name for x in ordered_networks]

            # all() will always return true if 'list' is empty
            if all(x in names for x in list) and len(names) > 0:
                return ordered_networks
            elif not scan_if_needed:
                return None

        condition = 'not obj.scanning'
        IWD._wait_for_object_condition(self, condition)

        try:
            # Do a full scan if instructed or if hostapd isn't being used
            if full_scan or not ctx.hostapd:
                self.scan()
            else:
                self.debug_scan(ctx.get_frequencies())
        except InProgressEx:
            pass

        condition = 'obj.scanning'
        IWD._wait_for_object_condition(self, condition)
        condition = 'not obj.scanning'
        IWD._wait_for_object_condition(self, condition)

        for bus_obj in self._station.GetOrderedNetworks():
            ordered_network = OrderedNetwork(bus_obj, self._bus, self._namespace)
            ordered_networks.append(ordered_network)

        if len(ordered_networks) > 0:
            return ordered_networks

        return None

    def get_ordered_network(self, network, scan_if_needed = True, full_scan = False):
        '''Returns a single network from ordered network call, or None if the
           network wasn't found. If the network is not found an exception is
           raised, this removes the need to extra asserts in autotests.
        '''
        def wait_for_network(self, network, scan_if_needed, full_scan):
            networks = self.get_ordered_networks(scan_if_needed, full_scan, list=[network])

            if not networks:
                # No point in continuing if we aren't going to re-scan
                if not scan_if_needed:
                    raise Exception("Network %s not found" % network)

                return False

            for n in networks:
                if n.name == network:
                    return n

            return False

        return ctx.non_block_wait(wait_for_network, 30, self, network, scan_if_needed, full_scan,
                                    exception=Exception("Network %s not found" % network))

    def wps_push_button(self):
        self._wps_manager.PushButton(dbus_interface=IWD_WSC_INTERFACE,
                                     reply_handler=self._success,
                                     error_handler=self._failure)
        self._wait_for_async_op()

    def wps_generate_pin(self):
        return self._wps_manager.GeneratePin()

    def wps_start_pin(self, pin):
        self._wps_manager.StartPin(pin, reply_handler=self._success,
                                        error_handler=self._failure)

    def wps_cancel(self):
        self._wps_manager.Cancel(dbus_interface=IWD_WSC_INTERFACE,
                                 reply_handler=self._success,
                                 error_handler=self._failure)
        self._wait_for_async_op()

    def register_signal_agent(self, signal_agent, levels):
        self._station.RegisterSignalLevelAgent(signal_agent.path,
                                        dbus.Array(levels, 'n'),
                                        dbus_interface=IWD_STATION_INTERFACE,
                                        reply_handler=self._success,
                                        error_handler=self._failure)
        self._wait_for_async_op()

    def unregister_signal_agent(self, signal_agent):
        self._station.UnregisterSignalLevelAgent(signal_agent.path,
                                        dbus_interface=IWD_STATION_INTERFACE,
                                        reply_handler=self._success,
                                        error_handler=self._failure)
        self._wait_for_async_op()

    def start_ap(self, ssid, psk=None):
        try:
            self._prop_proxy.Set(IWD_DEVICE_INTERFACE, 'Mode', 'ap')
        except Exception as e:
            raise _convert_dbus_ex(e)

        self._ap_iface = dbus.Interface(self._bus.get_object(IWD_SERVICE,
                                            self.device_path),
                                            IWD_AP_INTERFACE)
        if psk:
            self._ap_iface.Start(ssid, psk, reply_handler=self._success,
                                    error_handler=self._failure)
        else:
            self._ap_iface.StartProfile(ssid, reply_handler=self._success,
                                    error_handler=self._failure)
        self._wait_for_async_op()

    def stop_ap(self):
        self._prop_proxy.Set(IWD_DEVICE_INTERFACE, 'Mode', 'station')

    def connect_hidden_network(self, name):
        '''Connect to a hidden network
           Possible exception: BusyEx
                               FailedEx
                               InvalidArgumentsEx
                               NotConfiguredEx
                               NotConnectedEx
                               NotFoundEx
                               ServiceSetOverlapEx
        '''
        self._iface.ConnectHiddenNetwork(name,
                               dbus_interface=IWD_STATION_INTERFACE,
                               reply_handler=self._success,
                               error_handler=self._failure)
        self._wait_for_async_op()

    def connect_hidden_network_async(self, name, reply_handler, error_handler):
        '''Connect to a hidden network
           Possible exception: BusyEx
                               FailedEx
                               InvalidArgumentsEx
                               NotConfiguredEx
                               NotConnectedEx
                               NotFoundEx
                               ServiceSetOverlapEx
        '''
        self._iface.ConnectHiddenNetwork(name,
                               dbus_interface=IWD_STATION_INTERFACE,
                               reply_handler=reply_handler,
                               error_handler=error_handler)

    def start_adhoc(self, ssid, psk=None):
        self._prop_proxy.Set(IWD_DEVICE_INTERFACE, 'Mode', 'ad-hoc')
        self._adhoc_iface = dbus.Interface(self._bus.get_object(IWD_SERVICE,
                                            self.device_path),
                                            IWD_ADHOC_INTERFACE)
        if not psk:
            self._adhoc_iface.StartOpen(ssid, reply_handler=self._success,
                                        error_handler=self._failure)
        else:
            self._adhoc_iface.Start(ssid, psk, reply_handler=self._success,
                                        error_handler=self._failure)
        self._wait_for_async_op()

        return AdHocDevice(self.device_path)

    def stop_adhoc(self):
        self._prop_proxy.Set(IWD_DEVICE_INTERFACE, 'Mode', 'station')

    def connect_bssid(self, address):
        self._station_debug.connect_bssid(address)

    def roam(self, address):
        self._station_debug.roam(address)

    def debug_scan(self, frequencies):
        self._station_debug.scan(frequencies)

    def wait_for_event(self, event, timeout=10):
        self._station_debug.wait_for_event(event, timeout)

    def dpp_start_enrollee(self):
        return self._device_provisioning.start_enrollee()

    def dpp_start_configurator(self, uri=None):
        return self._device_provisioning.start_configurator(uri)

    def dpp_stop(self):
        return self._device_provisioning.stop()

    def __str__(self, prefix = ''):
        return prefix + 'Device: ' + self.device_path + '\n'\
               + prefix + '\tName:\t\t' + self.name + '\n'\
               + prefix + '\tAddress:\t' + self.address + '\n'\
               + prefix + '\tState:\t\t' + str(self.state) + '\n'\
               + prefix + '\tPowered:\t' + str(self.powered) + '\n'\
               + prefix + '\tConnected net:\t' + str(self.connected_network) +\
                                                                            '\n'


class Network(IWDDBusAbstract):
    '''Class represents a network object: net.connman.iwd.Network'''
    _iface_name = IWD_NETWORK_INTERFACE

    @property
    def name(self):
        '''
            Network SSID.

            @rtype: string
        '''
        return self._properties['Name']

    @property
    def connected(self):
        '''
            Reflects whether the device is connected to this network.

            @rtype: boolean
        '''
        return bool(self._properties['Connected'])

    def connect(self, wait=True):
        '''
            Connect to the network. Request the device implied by the object
            path to connect to specified network.

            Possible exception: AbortedEx
                                BusyEx
                                FailedEx
                                NoAgentEx
                                NotSupportedEx
                                TimeoutEx

            @rtype: void
        '''

        self._iface.Connect(dbus_interface=self._iface_name,
                            reply_handler=self._success,
                            error_handler=self._failure)

        if wait:
            self._wait_for_async_op()

    def __str__(self, prefix = ''):
        return prefix + 'Network:\n' \
                + prefix + '\tName:\t' + self.name + '\n' \
                + prefix + '\tConnected:\t' + str(self.connected)


class KnownNetwork(IWDDBusAbstract):
    '''Class represents a known network object: net.connman.iwd.KnownNetwork'''
    _iface_name = IWD_KNOWN_NETWORK_INTERFACE

    def forget(self):
        '''
        Removes information saved by IWD about this network
        causing it to be treated as if IWD had never connected
        to it before.
        '''
        self._iface.Forget(dbus_interface=self._iface_name,
                               reply_handler=self._success,
                               error_handler=self._failure)
        self._wait_for_async_op()

    @property
    def name(self):
        '''Contains the Name (SSID) of the network.'''
        return str(self._properties['Name'])

    @property
    def type(self):
        '''Contains the type of the network.'''
        return NetworkType(self._properties['Type'])

    @property
    def last_connected_time(self):
        '''
        Contains the last time this network has been connected to.
        If the network is known, but has never been successfully
        connected to, this attribute is set to None.

        @rtype: datetime
        '''
        if 'LastConnectedTime' not in self._properties:
            return None

        val = self._properties['LastConnectedTime']
        return datetime.datetime.strptime(val, "%Y-%m-%dT%H:%M:%SZ")

    def __str__(self, prefix = ''):
        return prefix + 'Known Network:\n' \
                + prefix + '\tName:\t' + self.name + '\n' \
                + prefix + '\tType:\t' + str(self.type) + '\n' \
                + prefix + '\tLast connected:\t' + str(self.last_connected_time)

class OrderedNetwork(object):
    '''Represents a network found in the scan'''

    def __init__(self, o_n_tuple, bus, namespace=ctx):
        self._bus = bus
        self._network_object = Network(o_n_tuple[0], namespace=namespace)
        self._network_proxy = dbus.Interface(self._bus.get_object(IWD_SERVICE,
                                        o_n_tuple[0]),
                                        DBUS_PROPERTIES)
        self._properties = self._network_proxy.GetAll(IWD_NETWORK_INTERFACE)

        self._name = self._properties['Name']
        self._signal_strength = o_n_tuple[1]
        self._type = NetworkType.from_string(str(self._properties['Type']))

    @property
    def network_object(self):
        '''
            net.connman.iwd.Network object representing the network.

            @rtype: Network
        '''
        return self._network_object

    @property
    def name(self):
        '''
            Device's interface name.

            @rtype: string
        '''
        return self._name

    @property
    def signal_strength(self):
        '''
            Network's maximum signal strength expressed in 100 * dBm.
            The value is the range of 0 (strongest signal) to
            -10000 (weakest signal)

            @rtype: number
        '''
        return self._signal_strength

    @property
    def type(self):
        '''
            Contains the type of the network.

            @rtype: NetworkType
        '''
        return self._type

    def __str__(self):
        return 'Ordered Network:\n'\
                '\tName:\t\t' + self._name + '\n'\
                '\tNetwork Type:\t' + str(self._type) + '\n'\
                '\tSignal Strength:'\
                    + ('None' if self.signal_strength is None else\
                        str(self.signal_strength)) + '\n'\
                '\tObject: \n' + self.network_object.__str__('\t\t')

agent_count = 0

class PSKAgent(dbus.service.Object):

    def __init__(self, passphrases=[], users=[], namespace=ctx):
        global agent_count

        if type(passphrases) != list:
            passphrases = [passphrases]
        self.passphrases = passphrases
        if type(users) != list:
            users = [users]
        self.users = users
        self._path = '/test/agent/%s' % agent_count
        self._bus = dbus.bus.BusConnection(address_or_type=namespace.dbus_address)

        agent_count += 1

        dbus.service.Object.__init__(self, self._bus, self._path)

    @property
    def path(self):
        return self._path

    @dbus.service.method(IWD_AGENT_INTERFACE, in_signature='', out_signature='')
    def Release(self):
        print("Agent released")

    @dbus.service.method(IWD_AGENT_INTERFACE, in_signature='s',
                                                               out_signature='')
    def Cancel(self, reason):
        print("Cancel: " + reason)


    @dbus.service.method(IWD_AGENT_INTERFACE, in_signature='o',
                                                              out_signature='s')
    def RequestPassphrase(self, path):
        print('Requested PSK for ' + path)

        if not self.passphrases:
            raise CanceledEx("canceled")

        return self.passphrases.pop(0)

    @dbus.service.method(IWD_AGENT_INTERFACE, in_signature='o',
                                                              out_signature='s')
    def RequestPrivateKeyPassphrase(self, path):
        print('Requested private-key passphrase for ' + path)

        if not self.passphrases:
            raise CanceledEx("canceled")

        return self.passphrases.pop(0)

    @dbus.service.method(IWD_AGENT_INTERFACE, in_signature='o',
                                                             out_signature='ss')
    def RequestUserNameAndPassword(self, path):
        print('Requested the user name and password for ' + path)

        if not self.users:
            raise CanceledEx("canceled")

        return self.users.pop(0)

    @dbus.service.method(IWD_AGENT_INTERFACE, in_signature='os',
                                                              out_signature='s')
    def RequestUserPassword(self, path, req_user):
        print('Requested the password for ' + path + ' for user ' + req_user)

        if not self.users:
            raise CanceledEx("canceled")

        user, passwd = self.users.pop(0)
        if user != req_user:
            raise CanceledEx("canceled")

        return passwd


class P2PDevice(IWDDBusAbstract):
    _iface_name = IWD_P2P_INTERFACE

    def __init__(self, *args, **kwargs):
        self._discovery_request = False
        self._peer_dict = {}
        IWDDBusAbstract.__init__(self, *args, **kwargs)

    @property
    def name(self):
        return str(self._properties['Name'])

    @name.setter
    def name(self, name):
        self._prop_proxy.Set(self._iface_name, 'Name', name)

    @property
    def enabled(self):
        return bool(self._properties['Enabled'])

    @enabled.setter
    def enabled(self, enabled):
        self._prop_proxy.Set(self._iface_name, 'Enabled', enabled)

    @property
    def discovery_request(self):
        return self._discovery_request

    @discovery_request.setter
    def discovery_request(self, req):
        if self._discovery_request == bool(req):
            return

        if bool(req):
            self._iface.RequestDiscovery()
        else:
            self._iface.ReleaseDiscovery()

        self._discovery_request = bool(req)

    def get_peers(self):
        old_dict = self._peer_dict
        self._peer_dict = {}

        for path, rssi in self._iface.GetPeers():
            self._peer_dict[path] = old_dict[path] if path in old_dict else P2PPeer(path, namespace=self._namespace)
            self._peer_dict[path].rssi = rssi

        return self._peer_dict


class P2PPeer(IWDDBusAbstract):
    _iface_name = IWD_P2P_PEER_INTERFACE

    @property
    def name(self):
        return str(self._properties['Name'])

    @property
    def category(self):
        return str(self._properties['DeviceCategory'])

    @property
    def subcategory(self):
        return str(self._properties['DeviceSubcategory'])

    @property
    def connected(self):
        return bool(self._properties['Connected'])

    @property
    def connected_interface(self):
        return str(self._properties['ConnectedInterface'])

    @property
    def connected_ip(self):
        return str(self._properties['ConnectedIP'])

    def connect(self, wait=True, pin=None):
        if pin is None:
            self._iface.PushButton(dbus_interface=IWD_WSC_INTERFACE,
                            reply_handler=self._success,
                            error_handler=self._failure)
        else:
            self._iface.StartPin(pin,
                            dbus_interface=IWD_WSC_INTERFACE,
                            reply_handler=self._success,
                            error_handler=self._failure)

        if wait:
            self._wait_for_async_op()
            return (self.connected_interface, self.connected_ip)

    def disconnect(self):
        self._iface.Disconnect()


class DeviceList(Mapping):
    def __init__(self, iwd):
        self._dict = {}
        self._p2p_dict = {}
        self._namespace = iwd.namespace

        iwd._object_manager.connect_to_signal("InterfacesAdded",
                                               self._interfaces_added_handler)
        iwd._object_manager.connect_to_signal("InterfacesRemoved",
                                               self._interfaces_removed_handler)

        objects = iwd._object_manager.GetManagedObjects()

        for path in objects:
            for interface in objects[path]:
                if interface == IWD_DEVICE_INTERFACE:
                    self._dict[path] = Device(path, objects[path][interface],
                                                namespace=self._namespace)
                elif interface == IWD_P2P_INTERFACE:
                    self._p2p_dict[path] = P2PDevice(path, objects[path][interface],
                                                namespace=self._namespace)

    def __getitem__(self, key):
        return self._dict.__getitem__(key)

    def __iter__(self):
        return self._dict.__iter__()

    def __len__(self):
        return self._dict.__len__()

    def __delitem__(self, key):
        self._dict.pop(key).remove()

    def _interfaces_added_handler(self, path, interfaces):
        if IWD_DEVICE_INTERFACE in interfaces:
            self._dict[path] = Device(path, interfaces[IWD_DEVICE_INTERFACE],
                                            namespace=self._namespace)
        elif IWD_P2P_INTERFACE in interfaces:
            self._p2p_dict[path] = P2PDevice(path, interfaces[IWD_P2P_INTERFACE],
                                            namespace=self._namespace)

    def _interfaces_removed_handler(self, path, interfaces):
        if IWD_DEVICE_INTERFACE in interfaces:
            del self._dict[path]
        elif IWD_P2P_INTERFACE in interfaces:
            del self._p2p_dict[path]

    @property
    def p2p_dict(self):
        return self._p2p_dict


class IWD(AsyncOpAbstract):
    '''
        Start an IWD instance. By default IWD should already be running, but
        some tests do require starting IWD using this constructor (by passing
        start_iwd_daemon=True)
    '''
    _default_instance = None

    def __init__(self, start_iwd_daemon = False, iwd_config_dir = '/tmp',
                            iwd_storage_dir = IWD_STORAGE_DIR, namespace=ctx,
                            developer_mode = True):
        self.namespace = namespace
        self._bus = namespace.get_bus()
        self._object_manager_if = None
        self._iwd_proc = None

        if start_iwd_daemon:
            if self.namespace.is_process_running('iwd'):
                raise Exception("IWD requested to start but is already running")

            self._iwd_proc = self.namespace.start_iwd(iwd_config_dir,
                                                        iwd_storage_dir,
                                                        developer_mode)

        self._devices = DeviceList(self)

        # Weak to make sure the test's reference to @self is the only counted
        # reference so that __del__ gets called when it's released. This is only
        # done for the root namespace in order to allow testutil to function
        # correctly in non-namespace tests.
        if self.namespace.name is None:
            IWD._default_instance = weakref.ref(self)

        self.psk_agents = []

    def __del__(self):
        for agent in self.psk_agents:
            self.unregister_psk_agent(agent)

        self.psk_agents = []

        self._object_manager_if = None
        self._known_networks = None
        self._devices = None

        if self._iwd_proc is not None:
            self.namespace.stop_process(self._iwd_proc)
            self._iwd_proc = None

        self.namespace = None

    @property
    def _object_manager(self):
        if self._object_manager_if is None:
            self._object_manager_if = \
                       dbus.Interface(self._bus.get_object(IWD_SERVICE,
                                                           IWD_TOP_LEVEL_PATH),
                                      DBUS_OBJECT_MANAGER)
        return self._object_manager_if

    @staticmethod
    def _wait_for_object_condition(obj, condition_str, max_wait = 50):
        def _eval_wrap(obj, condition_str):
            return eval(condition_str)

        ctx.non_block_wait(_eval_wrap, max_wait, obj, condition_str,
                            exception=TimeoutError('[' + condition_str + ']'\
                                                   ' condition was not met in '\
                                                   + str(max_wait) + ' sec'))

    def wait_for_object_condition(self, *args, **kwargs):
        self._wait_for_object_condition(*args, **kwargs)

    def wait_for_object_change(self, obj, from_str, to_str, max_wait = 50):
        '''
            Wait for 'from_str' to evaluate true then waits for 'to_str'. If
            at any point during the wait 'from_str' evaluates false, an exception is
            raised.

            This allows an object to be checked for a state transition without any
            intermediate state changes.
        '''
        def _eval_from_to(obj, from_str, to_str):
            # If neither the initial or expected condition evaluate the
            # object must be in another unexpected state.
            if not eval(from_str) and not eval(to_str):
                raise Exception('unexpected condition between [%s] and [%s]' %
                                        (from_str, to_str))

            # Initial condition does not evaluate but expected does, pass
            if not eval(from_str) and eval(to_str):
                return True

            return False

        # wait for initial condition
        self._wait_for_object_condition(obj, from_str)

        ctx.non_block_wait(_eval_from_to, max_wait, obj, from_str, to_str,
                            exception=TimeoutError('[' + to_str + ']'\
                                       ' condition was not met in '\
                                       + str(max_wait) + ' sec'))

    @staticmethod
    def wait(time):
        ctx.non_block_wait(lambda : False, time, exception=False)

    @staticmethod
    def clear_storage(storage_dir=IWD_STORAGE_DIR):
        os.system('rm -rf ' + storage_dir + '/*')
        os.system('rm -rf ' + storage_dir + '/hotspot/*')
        os.system('rm -rf ' + storage_dir + '/ap/*')

    @staticmethod
    def create_in_storage(file_name, file_content, storage_dir=IWD_STORAGE_DIR):
        fo = open(storage_dir + '/' + file_name, 'w')

        fo.write(file_content)
        fo.close()

    @staticmethod
    def _ensure_storage_dir_exists(storage_dir):
        if not os.path.exists(storage_dir):
            os.mkdir(storage_dir)

    @staticmethod
    def copy_to_storage(source, storage_dir=IWD_STORAGE_DIR, name=None):
        import shutil

        assert not os.path.isabs(source)

        target = storage_dir
        if name:
            target += '/%s' % name

        IWD._ensure_storage_dir_exists(storage_dir)
        shutil.copy(source, target)

    @staticmethod
    def copy_to_hotspot(source, storage_dir=IWD_STORAGE_DIR):
        IWD._ensure_storage_dir_exists(storage_dir)

        if not os.path.exists(storage_dir + "/hotspot"):
            os.mkdir(storage_dir + "/hotspot")

        IWD.copy_to_storage(source, storage_dir + "/hotspot")

    @staticmethod
    def copy_to_ap(source, storage_dir=IWD_STORAGE_DIR):
        if not os.path.exists(storage_dir + "/ap"):
            os.mkdir(storage_dir + "/ap")

        IWD.copy_to_storage(source, storage_dir + '/ap/')

    @staticmethod
    def remove_from_storage(file_name, storage_dir=IWD_STORAGE_DIR):
        os.system('rm -rf ' + storage_dir + '/\'' + file_name + '\'')

    def list_devices(self, wait_to_appear = 0, max_wait = 50, p2p = False):
        if not wait_to_appear:
            return list(self._devices.values() if not p2p else self._devices.p2p_dict.values())

        ctx.non_block_wait(lambda s, n: len(s._devices) >= n, max_wait, self, wait_to_appear,
                            exception=TimeoutError('IWD has no associated devices'))

        return list(self._devices.values() if not p2p else self._devices.p2p_dict.values())[:wait_to_appear]

    def list_p2p_devices(self, *args, **kwargs):
        return self.list_devices(*args, **kwargs, p2p=True)

    def list_known_networks(self):
        '''Returns the list of KnownNetwork objects.'''
        objects = self._object_manager.GetManagedObjects()
        known_network_list = []

        for path in objects:
            for interface in objects[path]:
                if interface == IWD_KNOWN_NETWORK_INTERFACE:
                    known_network_list.append(
                            KnownNetwork(path, objects[path][interface]))

        return known_network_list

    def register_psk_agent(self, psk_agent):
        iface = dbus.Interface(psk_agent._bus.get_object(IWD_SERVICE,
                                                IWD_AGENT_MANAGER_PATH),
                                                IWD_AGENT_MANAGER_INTERFACE)
        iface.RegisterAgent(psk_agent.path,
                            dbus_interface=IWD_AGENT_MANAGER_INTERFACE,
                            reply_handler=self._success,
                            error_handler=self._failure)

        self._wait_for_async_op()
        self.psk_agents.append(psk_agent)

    def unregister_psk_agent(self, psk_agent):
        iface = dbus.Interface(psk_agent._bus.get_object(IWD_SERVICE,
                                                IWD_AGENT_MANAGER_PATH),
                                                IWD_AGENT_MANAGER_INTERFACE)
        iface.UnregisterAgent(psk_agent.path,
                                dbus_interface=IWD_AGENT_MANAGER_INTERFACE,
                                reply_handler=self._success,
                                error_handler=self._failure)
        self._wait_for_async_op()
        self.psk_agents.remove(psk_agent)

    @staticmethod
    def get_instance():
        return IWD._default_instance()
