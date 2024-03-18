import unittest
import sys
import sys
import os
from scapy.layers.dot11 import *
from scapy.arch import str2mac, get_if_raw_hwaddr
from time import time, sleep
from threading import Thread

def if_hwaddr(iff):
    return str2mac(get_if_raw_hwaddr(iff)[1])

def config_mon(iface, channel):
  """set the interface in monitor mode and then change channel using iw"""
  os.system("ip link set dev %s down" % iface)
  os.system("iw dev %s set type monitor" % iface)
  os.system("ip link set dev %s up" % iface)
  os.system("iw dev %s set channel %d" % (iface, channel))

class AP:
    def __init__(self, ssid, psk, mac=None, mode="stdio", iface="wlan0", channel=1):
        self.channel = channel
        self.iface = iface
        self.mode = mode
        if self.mode == "iface":
            if not mac:
              mac = if_hwaddr(iface)
            config_mon(iface, channel)
        if not mac:
          raise Exception("Need a mac")
        else:
          self.mac = mac
        self.boottime = time()

    def get_radiotap_header(self):
        return RadioTap()

    def dot11_beacon(self, contents):
        evil_packet = (
            self.get_radiotap_header()
            / Dot11(
                subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=self.mac, addr3=self.mac
            )
            / Dot11Beacon(cap=0x3101)
            / contents
        )
        self.sendp(evil_packet)

    def run(self, contents):
        interval = 0.05
        num_beacons = 100

        while num_beacons:
            self.dot11_beacon(contents)
            sleep(interval)
            num_beacons -= 1

    def start(self, contents):
       self.thread = Thread(target=self.run, args=(contents,))
       self.thread.start()

    def stop(self):
       self.thread.join()

    def sendp(self, packet, verbose=False):
        if self.mode == "stdio":
            x = packet.build()
            sys.stdout.buffer.write(struct.pack("<L", len(x)) + x)
            sys.stdout.buffer.flush()
            return
        assert self.mode == "iface"
        sendp(packet, iface=self.iface, verbose=False)
