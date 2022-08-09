#! /usr/bin/python3
# Roughly based on wpa_supplicant's mac80211_hwsim/tools/hwsim_test.c utility.
import socket
import fcntl
import struct
import select
import codecs
import collections

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

def tx_packets(if0, if1, num):
    sock0, addr0 = raw_if_socket(if0)
    sock1, addr1 = raw_if_socket(if1)

    for i in range(num):
        tx(sock0, sock1, addr0, addr1)

def test_connected(if0=None, if1=None, group=True, expect_fail=False):
    if expect_fail:
        timeout = 0
    else:
        timeout = 10

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
            r, w, x = select.select([sock0, sock1], [], [], timeout)
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

def test_ifaces_connected(if0=None, if1=None, group=True, expect_fail=False):
    retry = 0
    while True:
        try:
            test_connected(if0, if1, group, expect_fail)
            break

        except Exception as e:
            if retry < 3 and not expect_fail:
                print('retrying connection test: %i' % retry)
                retry += 1
                continue
            raise e

SIOCGIFFLAGS = 0x8913
SIOCGIFADDR = 0x8915
SIOCGIFNETMASK = 0x891b
IFF_UP = 1 << 0
IFF_RUNNING = 1 << 6

def _test_operstate(intf):
    sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW)

    try:
        ifreq = struct.pack('16sh', intf.encode('utf8'), 0)
        flags = struct.unpack('16sh', fcntl.ioctl(sock, SIOCGIFFLAGS, ifreq))[1]

        # IFF_LOWER_UP and IFF_DORMANT not returned by SIOCGIFFLAGS
        if flags & (IFF_UP | IFF_RUNNING) != IFF_UP | IFF_RUNNING:
            return False

        return True
    finally:
        sock.close()

def test_iface_operstate(intf=None):
    if not intf:
        intf = iwd.IWD.get_instance().list_devices()[0].name

    ctx.non_block_wait(_test_operstate, 10, intf,
                        exception=Exception(intf + ' operstate wrong'))

def get_addrs6(ifname):
    f = open('/proc/net/if_inet6', 'r')
    lines = f.readlines()
    f.close()
    for line in lines:
        addr_str, _, plen, _, _, addr_ifname = line.split()
        if ifname is not None and addr_ifname != ifname:
            continue

        yield (codecs.decode(addr_str, 'hex'), int(plen, 16), addr_ifname)

def test_ip_address_match(intf, expected_addr_str, expected_plen=None, match_plen=None):
    def mask_addr(addr, plen):
        if plen is None or len(addr) * 8 <= plen:
            return addr
        bytelen = int(plen / 8)
        return addr[0:bytelen] + bytes([addr[bytelen] & (0xff00 >> (plen & 7))]) + b'\0' * (len(addr) - bytelen - 1)
    if expected_addr_str is not None:
        try:
            expected_addr = socket.inet_pton(socket.AF_INET, expected_addr_str)
            family = socket.AF_INET
        except OSError as e:
            try:
                expected_addr = socket.inet_pton(socket.AF_INET6, expected_addr_str)
                family = socket.AF_INET6
            except OSError as e2:
                raise e2 from None
        expected_addr = mask_addr(expected_addr, match_plen)
    else:
        expected_addr = None
        family = socket.AF_INET

    if family == socket.AF_INET:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            out = fcntl.ioctl(s.fileno(), SIOCGIFADDR, struct.pack('256s', intf.encode('utf-8')))
            actual_addr = mask_addr(out[20:24], match_plen)
            out = fcntl.ioctl(s.fileno(), SIOCGIFNETMASK, struct.pack('256s', intf.encode('utf-8')))
            actual_plen = sum([sum([(byte >> bit) & 1 for bit in range(0, 8)]) for byte in out[20:24]]) # count bits
        except OSError as e:
            if e.errno == 99 and expected_addr is None:
                return

            raise Exception('SIOCGIFADDR/SIOCGIFNETMASK failed with %d' % e.errno)
    else:
        # The "get" ioctls don't work for IPv6, netdevice(7) recommends reading /proc/net instead,
        # which on the other hand works *only* for IPv6
        actual_addr = None
        actual_plen = None
        for addr, plen, _ in get_addrs6(intf):
            actual_addr = mask_addr(addr, match_plen)
            actual_plen = plen
            if actual_addr == expected_addr:
                break

    if expected_addr != actual_addr:
        raise Exception('IP for %s did not match %s (was %s)' %
                        (intf, expected_addr_str, socket.inet_ntop(family, actual_addr)))

    if expected_plen is not None and expected_plen != actual_plen:
        raise Exception('Prefix Length for %s did not match %i (was %i)' %
                        (intf, expected_plen, actual_plen))

def test_ip_connected(tup0, tup1):
    ip0, ns0 = tup0
    ip1, ns1 = tup1

    try:
        ns0.start_process(['ping', '-c', '5', '-i', '0.2', ip1], check=True)
        ns1.start_process(['ping', '-c', '5', '-i', '0.2', ip0], check=True)
    except:
        raise Exception('Could not ping between %s and %s' % (ip0, ip1))

RouteInfo = collections.namedtuple('RouteInfo', 'dst plen gw flags ifname',
        defaults=(None, None, None, 0, ''))

def get_routes4(ifname=None):
    f = open('/proc/net/route', 'r')
    lines = f.readlines()
    f.close()
    for line in lines[1:]: # Skip header line
        route_ifname, dst_str, gw_str, flags, ref_cnt, use_cnt, metric, mask_str, \
                mtu = line.strip().split(maxsplit=8)
        if ifname is not None and route_ifname != ifname:
            continue

        dst = codecs.decode(dst_str, 'hex')[::-1]
        mask = int(mask_str, 16)
        plen = sum([(mask >> bit) & 1 for bit in range(0, 32)]) # count bits
        gw = codecs.decode(gw_str, 'hex')[::-1]

        if dst == b'\0\0\0\0':
            dst = None
            plen = None
        if gw == b'\0\0\0\0':
            gw = None
        yield RouteInfo(dst, plen, gw, int(flags, 16), route_ifname)

def get_routes6(ifname=None):
    f = open('/proc/net/ipv6_route', 'r')
    lines = f.readlines()
    f.close()
    for line in lines:
        dst_str, dst_plen_str, src_str, src_plen_str, gw_str, metric, ref_cnt, \
                use_cnt, flags, route_ifname = line.strip().split(maxsplit=9)
        if ifname is not None and route_ifname != ifname:
            continue

        dst = codecs.decode(dst_str, 'hex')
        plen = int(dst_plen_str, 16)
        gw = codecs.decode(gw_str, 'hex')

        if dst[0] == 0xff or dst[:2] == b'\xfe\x80': # Skip link-local and multicast
            continue

        # Skip RTN_LOCAL-type routes, we don't need to validate them since they're added by
        # the kernel and we can't simply add them to the expected list (the list that we
        # validate against) because they're added a short time after an address (due to DAD?)
        # and would create race conditions
        if int(flags, 16) & (1 << 31):
            continue

        if dst == b'\0' * 16:
            dst = None
            plen = None
        if gw == b'\0' * 16:
            gw = None
        yield RouteInfo(dst, plen, gw, int(flags, 16) & 0xf, route_ifname)
