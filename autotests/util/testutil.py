#! /usr/bin/python3
# Roughly based on wpa_supplicant's mac80211_hwsim/tools/hwsim_test.c utility.
import socket
import fcntl
import struct
import select

import iwd
from config import ctx

HWSIM_ETHERTYPE = 0x0800
HWSIM_PACKETLEN = 250

def raw_if_socket(intf):
    sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW,
                         socket.htons(HWSIM_ETHERTYPE))

    sock.bind((intf, HWSIM_ETHERTYPE))

    return (sock, sock.getsockname()[4])

def checksum(buf):
    pairs = zip(buf[0::2], buf[1::2])
    s = sum([(h << 8) + l for h, l in pairs])

    while s >> 16:
        s = (s & 0xffff) + (s >> 16)

    return s ^ 0xffff

def tx(fromsock, tosock, src, dst):
    frame = b''.join([
        dst, # eth.rmac
        src, # eth.lmac
        struct.pack('!H', HWSIM_ETHERTYPE), # eth.type
        b'\x45', # ip.hdr_len
        b'\x00', # ip.dsfield
        struct.pack('!H', HWSIM_PACKETLEN - 14), # ip.len
        b'\x01\x23', # ip.id
        b'\x40\x00', # ip.flags, ip.frag_offset
        b'\x40', # ip.ttl
        b'\x01', # ip.proto
        struct.pack('>H', 0), # ip.checksum
        socket.inet_aton('192.168.1.1'), # ip.src
        socket.inet_aton('192.168.1.2'), # ip.dst
        bytes(range(0, HWSIM_PACKETLEN - 14 - 20))
    ])
    frame = frame[:24] + struct.pack('>H', checksum(frame[14:34])) + frame[26:]

    fromsock.send(frame)

    return (frame, fromsock, tosock, src, dst)

def test_connected(if0=None, if1=None, group=True):
    if if0 is None or if1 is None:
        iwd_list = [dev.name for dev in iwd.IWD.get_instance().list_devices()]

        non_iwd_list = [rad.interface.name for rad in ctx.radios if rad.interface is not None]

        for intf in iwd_list + non_iwd_list:
            if if0 is None:
                if0 = intf
            elif if1 is None and intf != if0:
                if1 = intf

    sock0, addr0 = raw_if_socket(if0)
    sock1, addr1 = raw_if_socket(if1)
    bcast = b'\xff\xff\xff\xff\xff\xff'

    try:
        frames = [
            tx(sock0, sock1, addr0, addr1),
            tx(sock1, sock0, addr1, addr0),
        ]

        rec = [False, False]

        if group:
            frames.append(tx(sock0, sock1, addr0, bcast))
            frames.append(tx(sock1, sock0, addr1, bcast))
            rec.append(False)
            rec.append(False)

        while not all(rec):
            r, w, x = select.select([sock0, sock1], [], [], 10)
            if not r:
                raise Exception('timeout waiting for packets: ' + repr(rec))

            for s in r:
                data, src = s.recvfrom(HWSIM_PACKETLEN + 1)
                print('received ' + repr(data[:40]) + '... from ' + str(src))
                if len(data) != HWSIM_PACKETLEN:
                    continue

                idx = 0
                for origdata, fromsock, tosock, origsrc, origdst in frames:
                    if s is tosock and src[4] == origsrc and data == origdata:
                        print('matches frame ' + str(idx))
                        break
                    idx += 1
                else:
                    print('doesn\'t match any of our frames')
                    continue

                if rec[idx]:
                    raise Exception('duplicate frame ' + str(idx))

                rec[idx] = True
    finally:
        sock0.close()
        sock1.close()

def test_ifaces_connected(if0=None, if1=None, group=True):
    retry = 0
    while True:
        try:
            test_connected(if0, if1, group)
            break

        except Exception as e:
            if retry < 3:
                print('retrying connection test: %i' % retry)
                retry += 1
                continue
            raise e

SIOCGIFFLAGS = 0x8913
SIOCGIFADDR = 0x8915
IFF_UP = 1 << 0
IFF_RUNNING = 1 << 6

def test_iface_operstate(intf=None):
    if not intf:
        intf = iwd.IWD.get_instance().list_devices()[0].name

    sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW)

    try:
        ifreq = struct.pack('16sh', intf.encode('utf8'), 0)
        flags = struct.unpack('16sh', fcntl.ioctl(sock, SIOCGIFFLAGS, ifreq))[1]

        # IFF_LOWER_UP and IFF_DORMANT not returned by SIOCGIFFLAGS
        if flags & (IFF_UP | IFF_RUNNING) != IFF_UP | IFF_RUNNING:
            raise Exception(intf + ' operstate wrong')
    finally:
        sock.close()

def test_ip_address_match(intf, ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    addr = fcntl.ioctl(s.fileno(), SIOCGIFADDR, struct.pack('256s', intf.encode('utf-8')))
    addr = socket.inet_ntoa(addr[20:24])

    if ip != addr:
        raise Exception('IP for %s did not match %s (was %s)' % (intf, ip, addr))

def test_ip_connected(tup0, tup1):
    ip0, ns0 = tup0
    ip1, ns1 = tup1

    try:
        ns0.start_process(['ping', '-c', '5', '-i', '0.2', ip1], check=True)
        ns1.start_process(['ping', '-c', '5', '-i', '0.2', ip0], check=True)
    except:
        raise Exception('Could not ping between %s and %s' % (ip0, ip1))
