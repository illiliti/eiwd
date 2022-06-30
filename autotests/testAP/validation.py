from iwd import PSKAgent
from iwd import NetworkType
from hostapd import HostapdCLI
import testutil

def validate(wd, sta_dev, ap_dev, ssid, passphrase,
                sta_ip_info=None, ap_ip_info=None, ip_checks=True):
    try:
        network = sta_dev.get_ordered_network(ssid, full_scan=True)

        if network.type != NetworkType.psk:
            raise Exception("Network type mismatch")

        psk_agent = PSKAgent(passphrase)
        wd.register_psk_agent(psk_agent)

        network.network_object.connect()

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(sta_dev, condition)

        testutil.test_iface_operstate(sta_dev.name)

        # This implies separate namespaces so the iface names won't exist
        if not sta_ip_info or not ap_ip_info:
            testutil.test_ifaces_connected(ap_dev.name, sta_dev.name, group=False)

        if not ip_checks:
            return

        if sta_ip_info:
            testutil.test_ip_address_match(sta_dev.name, sta_ip_info[0])

        if sta_ip_info and ap_ip_info:
            testutil.test_ip_connected(sta_ip_info, ap_ip_info)

        wd.unregister_psk_agent(psk_agent)

        sta_dev.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(network.network_object, condition)
    finally:
        if ip_checks:
            ap_dev.stop_ap()

def client_connect(wd, dev, ssid):
    hostapd = HostapdCLI(config='psk-ccmp.conf')

    ordered_network = dev.get_ordered_network(ssid)

    if ordered_network.type != NetworkType.psk:
        raise Exception("Network type mismatch")

    psk_agent = PSKAgent('Password1')
    wd.register_psk_agent(psk_agent)

    ordered_network.network_object.connect()

    condition = 'obj.state == DeviceState.connected'
    wd.wait_for_object_condition(dev, condition)

    wd.unregister_psk_agent(psk_agent)

    testutil.test_iface_operstate(dev.name)
    testutil.test_ifaces_connected(hostapd.ifname, dev.name)

    dev.disconnect()

    condition = 'not obj.connected'
    wd.wait_for_object_condition(ordered_network.network_object, condition)
