import dbus
import time
from gi.repository import GLib
from config import ctx

SIM_AUTH_IFACE = 'org.ofono.SimAuthentication'

class Ofono(dbus.service.Object):
    def __init__(self, namespace=ctx):
        self._bus = namespace.get_bus()

        ctx.non_block_wait(self._bus.name_has_owner, 10, 'org.ofono',
                            exception=TimeoutError('Waiting for org.ofono service timed out'))

    def enable_modem(self, path):
        self._modem_path = path
        self._modem_iface = dbus.Interface(
                                        self._bus.get_object('org.ofono', path),
                                        'org.ofono.Modem')
        self._modem_iface.SetProperty("Powered", dbus.Boolean(1),
                                       timeout = 120)

    def _modem_prop_changed(self, property, changed):
        if property == 'Interfaces':
            if SIM_AUTH_IFACE in changed:
                self._sim_auth_up = True

    def wait_for_sim_auth(self, max_wait = 15):
        self._sim_auth_up = False

        props = self._modem_iface.GetProperties()
        if SIM_AUTH_IFACE in props['Interfaces']:
            self._sim_auth_up = True
            return

        self._modem_iface.connect_to_signal('PropertyChanged',
                                             self._modem_prop_changed)

        ctx.non_block_wait(lambda s : s._sim_auth_up, max_wait, self,
                            exception=TimeoutError('waiting for SimAuthetication timed out'))
