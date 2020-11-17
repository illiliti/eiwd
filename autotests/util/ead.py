#!/usr/bin/python3

from gi.repository import GLib
import dbus
import time
import collections

import iwd
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


class AdapterList(collections.Mapping):
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
        tries = 0
        while not self._bus.name_has_owner(EAD_SERVICE):
            if tries > 200:
                raise TimeoutError('IWD has failed to start')
            tries += 1
            time.sleep(0.1)

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

        self._wait_timed_out = False
        def wait_timeout_cb():
            self._wait_timed_out = True
            return False

        try:
            timeout = GLib.timeout_add_seconds(max_wait, wait_timeout_cb)
            context = ctx.mainloop.get_context()
            while len(self._adapters) < wait_to_appear:
                context.iteration(may_block=True)
                if self._wait_timed_out:
                    raise TimeoutError('IWD has no associated devices')
        finally:
            if not self._wait_timed_out:
                GLib.source_remove(timeout)

        return list(self._adapters.values())

    def wait_for_object_condition(self, obj, condition_str, max_wait = 50):
        self._wait_timed_out = False
        def wait_timeout_cb():
            self._wait_timed_out = True
            return False

        try:
            timeout = GLib.timeout_add_seconds(max_wait, wait_timeout_cb)
            context = ctx.mainloop.get_context()
            while not eval(condition_str):
                context.iteration(may_block=True)
                if self._wait_timed_out and ctx.args.gdb == None:
                    raise TimeoutError('[' + condition_str + ']'\
                                       ' condition was not met in '\
                                       + str(max_wait) + ' sec')
        finally:
            if not self._wait_timed_out:
                GLib.source_remove(timeout)
