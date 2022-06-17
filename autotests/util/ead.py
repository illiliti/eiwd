#!/usr/bin/python3

from gi.repository import GLib
import dbus
import time

import iwd
from collections.abc import Mapping
from config import ctx

EAD_SERVICE =                   'net.connman.ead'
EAD_ADAPTER_INTERFACE =         'net.connman.ead.Adapter'
DBUS_OBJECT_MANAGER =           'org.freedesktop.DBus.ObjectManager'
DBUS_PROPERTIES =               'org.freedesktop.DBus.Properties'
EAD_TOP_LEVEL_PATH =            '/'

class Adapter(iwd.IWDDBusAbstract):
    _iface_name = "net.connman.ead.Adapter"

    @property
    def name(self):
        return self._properties['Name']

    @property
    def address(self):
        return self._properties['Address']

    @property
    def active(self):
        return self._properties['Active']

    @property
    def connected(self):
        return self._properties['Connected']

    @property
    def authenticated(self):
        return self._properties['Authenticated']


class AdapterList(Mapping):
    def __init__(self, ead):
        self._dict = {}

        ead._object_manager.connect_to_signal("InterfacesAdded",
                                               self._interfaces_added_handler)
        ead._object_manager.connect_to_signal("InterfacesRemoved",
                                               self._interfaces_removed_handler)

        objects = ead._object_manager.GetManagedObjects()

        for path in objects:
            for interface in objects[path]:
                if interface == EAD_ADAPTER_INTERFACE:
                    self._dict[path] = Adapter(path, objects[path][interface], service=EAD_SERVICE)

    def __getitem__(self, key):
        return self._dict.__getitem__(key)

    def __iter__(self):
        return self._dict.__iter__()

    def __len__(self):
        return self._dict.__len__()

    def __delitem__(self, key):
        self._dict.pop(key).remove()

    def _interfaces_added_handler(self, path, interfaces):
        if EAD_ADAPTER_INTERFACE in interfaces:
            self._dict[path] = Adapter(path, interfaces[EAD_ADAPTER_INTERFACE], service=EAD_SERVICE)

    def _interfaces_removed_handler(self, path, interfaces):
        if EAD_ADAPTER_INTERFACE in interfaces:
            del self._dict[path]

class EAD(iwd.AsyncOpAbstract):
    _bus = ctx.get_bus()

    _object_manager_if = None
    _adapters = None

    def __init__(self):
        ctx.non_block_wait(self._bus.name_has_owner, 20, EAD_SERVICE,
                            exception=TimeoutError('EAD has failed to start'))

        self._adapters = AdapterList(self)

    @property
    def _object_manager(self):
        if self._object_manager_if is None:
            self._object_manager_if = \
                       dbus.Interface(self._bus.get_object(EAD_SERVICE,
                                                           EAD_TOP_LEVEL_PATH),
                                      DBUS_OBJECT_MANAGER)
        return self._object_manager_if

    def list_adapters(self, wait_to_appear = 0, max_wait = 50):
        if not wait_to_appear:
            return list(self._adapters.values())

        ctx.non_block_wait(lambda s, num : len(s._adapters) >= num, max_wait, self, wait_to_appear,
                            exception=TimeoutError('EAD has no associated devices'))

        return list(self._adapters.values())
