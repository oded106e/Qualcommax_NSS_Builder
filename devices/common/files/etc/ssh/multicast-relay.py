#!/usr/bin/env python3

import argparse
import binascii
import errno
import json
import http.server
import os
import re
import select
import socket
import struct
import sys
import threading
import time

# Al Smith <ajs@aeschi.eu> January 2018
# https://github.com/alsmith/multicast-relay

class Logger():
    def __init__(self, foreground, logfile, verbose):
        self.verbose = verbose

        try:
            import logging
            import logging.handlers
            self.loggingAvailable = True

            logger = logging.getLogger()
            syslog_handler = logging.handlers.SysLogHandler()
            syslog_handler.setFormatter(logging.Formatter(fmt='%(name)s[%(process)d] %(levelname)s: %(message)s'))
            logger.addHandler(syslog_handler)

            if foreground:
                stream_handler = logging.StreamHandler(sys.stdout)
                stream_handler.setFormatter(logging.Formatter(fmt='%(asctime)s %(name)s %(levelname)s: %(message)s', datefmt='%b-%d %H:%M:%S'))
                logger.addHandler(stream_handler)

            if logfile:
                file_handler = logging.FileHandler(logfile)
                file_handler.setFormatter(logging.Formatter(fmt='%(asctime)s %(name)s %(levelname)s: %(message)s', datefmt='%b-%d %H:%M:%S'))
                logger.addHandler(file_handler)

            if verbose:
                logger.setLevel(logging.INFO)
            else:
                logger.setLevel(logging.WARN)

        except ImportError:
            self.loggingAvailable = False

    def info(self, *args, **kwargs):
        if self.loggingAvailable:
            import logging
            logging.getLogger(__file__).info(*args, **kwargs)
        elif self.verbose:
            print(args, kwargs)

    def warning(self, *args, **kwargs):
        if self.loggingAvailable:
            import logging
            logging.getLogger(__file__).warning(*args, **kwargs)
        else:
            print(args, kwargs)

class Netifaces():
    """
    Self-contained stand-in for the third-party 'netifaces' package.

    netifaces is unmaintained upstream and, as of OpenWrt 25.12, is no
    longer available as an opkg package (python3-netifaces was dropped
    from the feed). This talks to the kernel directly via a handful of
    ioctl() calls instead, so nothing beyond the Python standard library
    (fcntl/array/socket/struct, all part of python3-light) is required.
    """
    AF_LINK = 1
    AF_INET = 2

    def __init__(self, ifNameStructLen=None):
        # struct ifreq, as filled in by SIOCGIFCONF, is 32 bytes on
        # 32-bit userspace and 40 bytes on 64-bit userspace. Most OpenWrt
        # targets (mips, arm, etc.) are 32-bit, so auto-detect this from
        # the interpreter's native pointer size instead of assuming
        # 64-bit. --ifNameStructLen can still be passed to override this
        # if a particular target needs something different.
        self.ifNameStructLen = ifNameStructLen or (40 if struct.calcsize('P') == 8 else 32)
        self.interfaceAttrs = {}

    def interfaces(self):
        import array
        import fcntl

        maxInterfaces = 128
        bufsiz = maxInterfaces * self.ifNameStructLen
        nullByte = b'\0'

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ifNames = array.array('B', nullByte * bufsiz)
        ifNameLen = struct.unpack('iL', fcntl.ioctl(
            s.fileno(),
            0x8912, # SIOCGIFCONF
            struct.pack('iL', bufsiz, ifNames.buffer_info()[0])
        ))[0]

        if ifNameLen % self.ifNameStructLen != 0:
            print('Do you need to set --ifNameStructLen? %s/%s ought to have a remainder of zero.' % (ifNameLen, self.ifNameStructLen))
            sys.exit(1)

        ifNames = ifNames.tobytes()
        for i in range(0, ifNameLen, self.ifNameStructLen):
            name      = ifNames[i:i+16].split(nullByte, 1)[0].decode()
            if not name:
                print('Cannot determine interface name: do you need to set --ifNameStructLen? %s/%s ought to have a remainder of zero.' % (ifNameLen, self.ifNameStructLen))
                sys.exit(1)
            ip        = socket.inet_ntoa(fcntl.ioctl(socket.socket(socket.AF_INET, socket.SOCK_DGRAM), 0x8915, struct.pack('256s', name.encode()))[20:24]) # SIOCGIFADDR
            netmask   = socket.inet_ntoa(fcntl.ioctl(socket.socket(socket.AF_INET, socket.SOCK_DGRAM), 0x891b, struct.pack('256s', name.encode()))[20:24]) # SIOCGIFNETMASK
            broadcast = socket.inet_ntoa(fcntl.ioctl(socket.socket(socket.AF_INET, socket.SOCK_DGRAM), 0x8919, struct.pack('256s', name.encode()))[20:24]) # SIOCGIFBRDADDR
            hwaddr    = ':'.join(['%02x' % char for char in fcntl.ioctl(socket.socket(socket.AF_INET, socket.SOCK_DGRAM), 0x8927, struct.pack('256s', name.encode()))[18:24]]) # SIOCGIFHWADDR
            self.interfaceAttrs[name] = {Netifaces.AF_LINK: [{'addr': hwaddr}], Netifaces.AF_INET: [{'addr': ip, 'netmask': netmask, 'broadcast': broadcast}]}
        return list(self.interfaceAttrs.keys())

    def ifaddresses(self, interface):
        return self.interfaceAttrs[interface]

class Cipher():
    def __init__(self, key):
        self.key = None
        if not key:
            return

        import Crypto.Cipher.AES
        import hashlib

        self.blockSize = Crypto.Cipher.AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    @staticmethod
    def strToInt(s):
        return int(binascii.hexlify(s), 16)

    def encrypt(self, plaintext):
        if not self.key:
            return plaintext

        import Crypto
        import Crypto.Random
        import Crypto.Util.Counter

        iv = Crypto.Random.new().read(self.blockSize)
        ctr = Crypto.Util.Counter.new(128, initial_value=self.strToInt(iv))
        aes = Crypto.Cipher.AES.new(self.key, Crypto.Cipher.AES.MODE_CTR, counter=ctr)
        return iv + aes.encrypt(plaintext)

    def decrypt(self, ciphertext):
        if not self.key:
            return ciphertext

        import Crypto
        import Crypto.Util.Counter

        iv = ciphertext[:self.blockSize]
        ctr = Crypto.Util.Counter.new(128, initial_value=self.strToInt(iv))
        aes = Crypto.Cipher.AES.new(self.key, Crypto.Cipher.AES.MODE_CTR, counter=ctr)
        return aes.decrypt(ciphertext[self.blockSize:])

class PacketRelay():
    MULTICAST_MIN     = '224.0.0.0'
    MULTICAST_MAX     = '239.255.255.255'
    BROADCAST         = '255.255.255.255'
    SSDP_MCAST_ADDR   = '239.255.255.250'
    SSDP_MCAST_PORT   = 1900
    SSDP_UNICAST_PORT = 1901
    MDNS_MCAST_ADDR   = '224.0.0.251'
    MDNS_MCAST_PORT   = 5353
    MAGIC             = b'MRLY'
    IPV4LEN           = len(socket.inet_aton('0.0.0.0'))

    def __init__(self, interfaces, noTransmitInterfaces, ifFilter, waitForIP, ttl,
                 oneInterface, ifNameStructLen, allowNonEther,
                 ssdpUnicastAddr, ssdpRepeat, mdnsRepeat, mdnsForceUnicast, masquerade, listen, remote,
                 remotePort, remoteRetry, noRemoteRelay, aes, logger):
        self.interfaces = interfaces
        self.noTransmitInterfaces = noTransmitInterfaces or []

        if ifFilter:
            with open(ifFilter) as fd:
                self.ifFilter = json.loads(fd.read().replace('\n', ' ').strip())
        else:
            self.ifFilter = {}
        self.ssdpUnicastAddr = ssdpUnicastAddr
        # Some SSDP-capable devices (several LG webOS TVs and some Fire TV /
        # Alexa devices observed in the wild) reliably announce themselves via
        # periodic NOTIFY (ssdp:alive) but never answer unicast M-SEARCH
        # requests. Clients that rely on catching that NOTIFY tend to show the
        # device flickering in and out as their own internal cache ages out
        # between the device's own NOTIFY bursts (which can be 1-2 minutes
        # apart). ssdpRepeat, if set, makes the relay itself remember the most
        # recent 'alive' NOTIFY per device (keyed by USN) and re-transmit it
        # to the other interfaces every ssdpRepeat seconds - independent of
        # how often the device itself actually re-announces. A byebye and
        # CACHE-CONTROL max-age are treated as reasons to re-check a device,
        # rather than removing an otherwise reachable TV immediately: webOS
        # is known to send transient byebyes while its discovery stack restarts.
        self.ssdpRepeat = ssdpRepeat
        self.notifyCache = {}
        # Google Cast, Android TV Remote and AirPlay discovery use mDNS, not
        # SSDP. Their useful A/SRV records commonly have a TTL of only 120
        # seconds. A plain multicast reflector forwards the initial packet
        # but then lets the remote network's cache expire. Keep complete mDNS
        # service responses with an SRV endpoint and re-announce them while
        # that endpoint remains reachable.
        self.mdnsRepeat = mdnsRepeat
        self.mdnsCache = {}
        self.mdnsForceUnicast = mdnsForceUnicast
        self.wait = waitForIP
        self.ttl = ttl
        self.oneInterface = oneInterface
        self.allowNonEther = allowNonEther
        self.masquerade = masquerade or []

        self.nif = Netifaces(ifNameStructLen)
        self.logger = logger

        self.transmitters = []
        self.receivers = []
        self.etherAddrs = {}
        self.etherType = struct.pack('!H', 0x0800)
        self.udpMaxLength = 1458

        self.recentChecksums = []

        self.bindings = set()

        self.listenAddr = []
        if listen:
            for addr in listen:
                components = addr.split('/')
                if len(components) == 1:
                    components.append('32')
                if not components[1].isdigit():
                    raise ValueError('--listen netmask is not an integer')
                if int(components[1]) not in range(0, 33):
                    raise ValueError('--listen netmask specifies an invalid netmask')
                self.listenAddr.append(components)

        self.listenSock = None
        if remote:
            self.remoteAddrs = list(map(lambda remote: {'addr': remote, 'socket': None, 'connecting': False, 'connectFailure': None}, remote))
        else:
            self.remoteAddrs = []
        self.remotePort = remotePort
        self.remoteRetry = remoteRetry
        self.noRemoteRelay = noRemoteRelay
        self.aes = Cipher(aes)

        self.remoteConnections = []

        if self.listenAddr:
            self.listenSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.listenSock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.listenSock.bind(('0.0.0.0', self.remotePort))
            self.listenSock.listen(0)
        elif self.remoteAddrs:
            self.connectRemotes()

    def connectRemotes(self):
        for remote in self.remoteAddrs:
            if remote['socket']:
                continue

            # Attempt reconnection at most once every N seconds
            if remote['connectFailure'] and remote['connectFailure'] > time.time()-self.remoteRetry:
                return

            remoteConnection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remoteConnection.setblocking(0)
            self.logger.info('REMOTE: Connecting to remote %s' % remote['addr'])
            remote['connecting'] = True
            try:
                remoteConnection.connect((remote['addr'], self.remotePort))
            except socket.error as e:
                if e.errno == errno.EINPROGRESS:
                    remote['socket'] = remoteConnection
                else:
                    remote['connecting'] = False
                    remote['connectFailure'] = time.time()

    def removeConnection(self, s):
        if s in self.remoteConnections:
            self.remoteConnections.remove(s)
            return

        for remote in self.remoteAddrs:
            if remote['socket'] == s:
                remote['socket'] = None
                remote['connecting'] = False
                remote['connectFailure'] = time.time()

    def remoteSockets(self):
        return self.remoteConnections + list(map(lambda remote: remote['socket'], filter(lambda remote: remote['socket'], self.remoteAddrs)))

    def addListener(self, addr, port, service):
        if self.isBroadcast(addr):
            self.etherAddrs[addr] = self.broadcastIpToMac(addr)
        elif self.isMulticast(addr):
            self.etherAddrs[addr] = self.multicastIpToMac(addr)
        else:
            # unicast -- we don't know yet which IP we'll want to send to
            self.etherAddrs[addr] = None

            rx = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            rx.bind((addr, port))
            self.receivers.append(rx)

        # Set up the receiving socket and corresponding IP and interface information.
        # One receiving socket is required per multicast address. But for extra
        # fun, one receiving socket for each network interface, if we're
        # intercepting broadcast packets.
        if self.isMulticast(addr):
            rx = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        for interface in self.interfaces:
            (ifname, mac, ip, netmask, broadcast) = self.getInterface(interface)

            # Add this interface to the receiving socket's list.
            if self.isBroadcast(addr):
                rx = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
                rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                rx.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

                if 'SO_BINDTODEVICE' not in dir(socket):
                    socket.SO_BINDTODEVICE = 25

                rx.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, ifname.encode('utf-8'))

                rx.bind(('0.0.0.0', port))

                self.receivers.append(rx)
                self.bindings.add((broadcast, port))
                listenIP = '255.255.255.255'

            elif self.isMulticast(addr):
                packedAddress = struct.pack('4s4s', socket.inet_aton(addr), socket.inet_aton(ip))
                rx.setsockopt(socket.SOL_IP, socket.IP_ADD_MEMBERSHIP, packedAddress)
                listenIP = addr
            else:
                listenIP = addr

            # Generate a transmitter socket. Each interface
            # requires its own transmitting socket.
            if interface not in self.noTransmitInterfaces:
                tx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
                tx.bind((ifname, 0))

                self.transmitters.append({'relay': {'addr': listenIP, 'port': port}, 'interface': ifname, 'addr': ip, 'mac': mac, 'netmask': netmask, 'broadcast': broadcast, 'socket': tx, 'service': service})

        if self.isMulticast(addr):
            rx.bind((addr, port))
            self.receivers.append(rx)
        self.bindings.add((addr, port))

    @staticmethod
    def unicastIpToMac(ip, procNetArp=None):
        """
        Return the mac address (as a string) of ip
        If procNetArp is not None, then it will be used instead
        of reading /proc/net/arp (useful for unit tests).
        """
        if procNetArp:
            arpTable = procNetArp
        else:
            # The arp table should be fairly small -- read it all in one go
            with open('/proc/net/arp', 'r') as fd:
                arpTable = fd.read()

        # Format:
        # IP address       HW type     Flags       HW address            Mask     Device
        # 192.168.0.1      0x1         0x2         18:90:22:bf:3c:23     *        wlp2s0
        matches = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s.*\s(([a-fA-F\d]{1,2}\:){5}[a-fA-F\d]{1,2})', arpTable)

        # We end up with tuples of 3 groups: (ip, mac, one_of_the_mac_sub_group)
        # We remove the 3rd one which allows us to create a dictionary:
        ip2mac = dict([t[0:2] for t in matches])

        # Default to None if key not in dict
        return ip2mac.get(ip, None)

    @staticmethod
    def modifyUdpPacket(data, ipHeaderLength, srcAddr=None, srcPort=None, dstAddr=None, dstPort=None):
        srcAddr = srcAddr if srcAddr else socket.inet_ntoa(data[12:16])
        dstAddr = dstAddr if dstAddr else socket.inet_ntoa(data[16:20])

        srcPort = srcPort if srcPort else struct.unpack('!H', data[ipHeaderLength+0:ipHeaderLength+2])[0]
        dstPort = dstPort if dstPort else struct.unpack('!H', data[ipHeaderLength+2:ipHeaderLength+4])[0]

        # Recreate the packet
        ipHeader = data[:ipHeaderLength-8] + socket.inet_aton(srcAddr) + socket.inet_aton(dstAddr)

        udpData = data[ipHeaderLength+8:]
        udpLength = 8 + len(udpData)
        udpHeader = struct.pack('!4H', srcPort, dstPort, udpLength, 0)

        return ipHeader + udpHeader + udpData

    @staticmethod
    def mdnsSetUnicastBit(data, ipHeaderLength):
        headers = data[:ipHeaderLength+8]
        udpData = data[ipHeaderLength+8:]

        flags = struct.unpack('!H', udpData[2:4])[0]
        if flags & 0x8000 != 0:
            return data

        queries = struct.unpack('!H', udpData[4:6])[0]

        queryCount = 0
        ptr = 12
        while True:
            labelLength = struct.unpack('B', udpData[ptr:ptr+1])[0]
            if not labelLength & 0x3f:
                if labelLength & 0xc0:
                    ptr += 1
                queryCount += 1
                data = struct.unpack('!H', udpData[ptr+3:ptr+5])[0]
                udpData = udpData[:ptr+3] + struct.pack('!H', data | 0x8000) + udpData[ptr+5:]
                if queryCount == queries:
                    break
                ptr += 5
            else:
                ptr += labelLength+1

        return headers + udpData

    def computeIPChecksum(self, data, ipHeaderLength):
        # Zero out current checksum
        data = data[:10] + struct.pack('!H', 0) + data[12:]

        # Recompute the IP header checksum
        checksum = 0
        for i in range(0, ipHeaderLength, 2):
            checksum += struct.unpack('!H', data[i:i+2])[0]

        while checksum > 0xffff:
            checksum = (checksum & 0xffff) + ((checksum - (checksum & 0xffff)) >> 16)

        checksum = ~checksum & 0xffff
        self.recentChecksums.append(checksum)
        if len(self.recentChecksums) > 256:
            self.recentChecksums = self.recentChecksums[1:]

        return data[:10] + struct.pack('!H', checksum) + data[12:]

    @staticmethod
    def computeUDPChecksum(ipHeader, udpHeader, data):
        pseudoIPHeader = ipHeader[12:20]+struct.pack('x')+ipHeader[9:10]+udpHeader[4:6]

        udpPacket = pseudoIPHeader+udpHeader[:6]+struct.pack('xx')+data
        if len(udpPacket) % 2:
            udpPacket += struct.pack('x')

        # Recompute the UDP header checksum
        checksum = 0
        for i in range(0, len(udpPacket), 2):
            checksum += struct.unpack('!H', udpPacket[i:i+2])[0]

        while checksum > 0xffff:
            checksum = (checksum & 0xffff) + ((checksum - (checksum & 0xffff)) >> 16)

        checksum = ~checksum & 0xffff
        return udpHeader[:6]+struct.pack('!H', checksum)

    def transmitPacket(self, sock, srcMac, destMac, ipHeaderLength, ipPacket):
        ipHeader  = ipPacket[:ipHeaderLength]
        udpHeader = ipPacket[ipHeaderLength:ipHeaderLength+8]
        data      = ipPacket[ipHeaderLength+8:]
        dontFragment = ipPacket[6]
        if type(dontFragment) == str:
            dontFragment = ord(dontFragment)
        dontFragment = (dontFragment & 0x40) >> 6

        udpHeader = self.computeUDPChecksum(ipHeader, udpHeader, data)

        for boundary in range(0, len(data), self.udpMaxLength):
            dataFragment = data[boundary:boundary+self.udpMaxLength]
            totalLength = len(ipHeader) + len(udpHeader) + len(dataFragment)
            moreFragments = boundary+self.udpMaxLength < len(data)

            flagsOffset = boundary & 0x1fff
            if moreFragments:
                flagsOffset |= 0x2000
            elif dontFragment:
                flagsOffset |= 0x4000

            ipHeader = ipHeader[:2]+struct.pack('!H', totalLength)+ipHeader[4:6]+struct.pack('!H', flagsOffset)+ipHeader[8:]
            ipPacket = self.computeIPChecksum(ipHeader + udpHeader + dataFragment, ipHeaderLength)

            try:
                if srcMac != binascii.unhexlify('00:00:00:00:00:00'.replace(':', '')):
                    etherPacket = destMac + srcMac + self.etherType + ipPacket
                    sock.send(etherPacket)
                else:
                    sock.send(ipPacket)
            except Exception as e:
                if e.errno == errno.ENXIO:
                    raise
                else:
                    self.logger.info('Error sending packet: %s' % str(e))

    def match(self, addr, port):
        return ((addr, port)) in self.bindings

    @staticmethod
    def parseSsdpNotifyHeaders(data, ipHeaderLength):
        # UDP payload starts 8 bytes past the end of the (variable-length) IP header
        payload = data[ipHeaderLength+8:]
        try:
            text = payload.decode('utf-8', 'ignore')
        except Exception:
            return (None, None, None, None, None)

        usn = re.search(r'^USN:\s*(.+?)\r?$', text, re.IGNORECASE | re.MULTILINE)
        nts = re.search(r'^NTS:\s*(.+?)\r?$', text, re.IGNORECASE | re.MULTILINE)
        maxAge = re.search(r'^CACHE-CONTROL:\s*.*max-age\s*=\s*(\d+)', text, re.IGNORECASE | re.MULTILINE)
        location = re.search(r'^LOCATION:\s*https?://([^:/\s]+)(?::(\d+))?', text, re.IGNORECASE | re.MULTILINE)

        usn = usn.group(1).strip() if usn else None
        nts = nts.group(1).strip().lower() if nts else None
        maxAge = int(maxAge.group(1)) if maxAge else 1800  # SSDP's own conventional default
        checkHost = location.group(1) if location else None
        checkPort = int(location.group(2)) if location and location.group(2) else (80 if checkHost else None)

        return (usn, nts, maxAge, checkHost, checkPort)

    def cacheSsdpNotify(self, data, addr, ttl, receivingInterface, ipHeaderLength):
        (usn, nts, maxAge, checkHost, checkPort) = PacketRelay.parseSsdpNotifyHeaders(data, ipHeaderLength)
        if not usn:
            return

        if nts == 'ssdp:byebye':
            if usn in self.notifyCache:
                # Several webOS builds send byebye while their UPnP process
                # restarts even though the TV is still serving its LOCATION.
                # Probe the cached endpoint before withdrawing it from other
                # networks; a genuinely offline device is removed after the
                # normal bounded liveness-failure threshold.
                self.notifyCache[usn]['lastSent'] = 0
                self.notifyCache[usn]['failCount'] = 0
                self.logger.info('[SSDP repeat] %s said byebye, verifying cached endpoint before removal' % usn)
            return

        if nts != 'ssdp:alive':
            return

        now = time.time()
        isNew = usn not in self.notifyCache
        # A fresh, real NOTIFY from the device is itself proof of life, so any
        # previous run of liveness-check failures is forgiven here.
        self.notifyCache[usn] = {
            'data': data,
            'addr': addr,
            'ttl': ttl,
            'receivingInterface': receivingInterface,
            'ipHeaderLength': ipHeaderLength,
            'lastSent': now,
            'expire': now + maxAge,
            'maxAge': maxAge,
            'checkHost': checkHost,
            'checkPort': checkPort,
            'failCount': 0,
        }
        if isNew:
            self.logger.info('[SSDP repeat] Caching %s (liveness check: %s), will re-announce every %ds until byebye or %ds max-age' %
                              (usn, checkHost and ('%s:%s' % (checkHost, checkPort)) or 'none available', self.ssdpRepeat, maxAge))

    # A cached announcement is only re-announced while its device still looks
    # reachable. This is a deliberately cheap, bounded, non-blocking TCP
    # reachability probe against the host:port from the SSDP LOCATION or mDNS
    # SRV record - not a full HTTP request. A completed handshake or a
    # connection refusal proves that the device's IP stack replied; webOS can
    # close a transient discovery port while the TV itself remains online.
    # Only a timeout/no-route is treated as an offline device.
    LIVENESS_CHECK_TIMEOUT = 0.3
    LIVENESS_CHECK_MAX_FAILURES = 2

    def isDeviceAlive(self, host, port):
        if not host or not port:
            # No LOCATION to check against - can't confirm either way, so
            # don't punish the entry for a header it never had.
            return True

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setblocking(False)
        try:
            try:
                s.connect((host, port))
            except BlockingIOError:
                pass
            except OSError as e:
                # ECONNREFUSED is a response from the remote IP stack. It
                # means this particular service is closed, not that the TV
                # disappeared from the network.
                return e.errno == errno.ECONNREFUSED

            (_, writable, _) = select.select([], [s], [], PacketRelay.LIVENESS_CHECK_TIMEOUT)
            if not writable:
                return False  # no response within the timeout at all

            # A refused connection (RST) also makes the socket 'writable'.
            # It is still positive host-liveness evidence; SO_ERROR tells it
            # apart from a successful service connection.
            err = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            return err == 0 or err == errno.ECONNREFUSED
        except Exception:
            return False
        finally:
            s.close()

    def replaySsdpCache(self):
        now = time.time()
        for usn in list(self.notifyCache.keys()):
            entry = self.notifyCache[usn]

            if now >= entry['expire']:
                # CACHE-CONTROL limits a receiver's cache, but does not prove
                # that an otherwise reachable device has disappeared. Keep a
                # live TV visible by renewing the relay's cache only after a
                # successful endpoint probe. An unreachable device still
                # follows the regular two-failure removal path below.
                entry['lastSent'] = now
                if self.isDeviceAlive(entry['checkHost'], entry['checkPort']):
                    entry['expire'] = now + entry['maxAge']
                    entry['failCount'] = 0
                    self.logger.info('[SSDP repeat] %s reached max-age but is still live; renewed cache for %ds' %
                                     (usn, entry['maxAge']))
                else:
                    entry['failCount'] += 1
                    self.logger.info('[SSDP repeat] max-age liveness check failed for %s (%s:%s) - %d/%d' %
                                     (usn, entry['checkHost'], entry['checkPort'], entry['failCount'], PacketRelay.LIVENESS_CHECK_MAX_FAILURES))
                    if entry['failCount'] >= PacketRelay.LIVENESS_CHECK_MAX_FAILURES:
                        del self.notifyCache[usn]
                        self.logger.info('[SSDP repeat] %s expired and failed liveness checks, dropped from cache' % usn)
                    else:
                        entry['expire'] = now + self.ssdpRepeat
                continue

            if now - entry['lastSent'] < self.ssdpRepeat:
                continue

            # Always advance lastSent on an attempt (pass or fail), so a
            # failing device is re-checked every ssdpRepeat seconds - not
            # every loop tick - and removal after LIVENESS_CHECK_MAX_FAILURES
            # takes roughly failures*ssdpRepeat seconds of being unreachable,
            # not a couple of seconds (which would make it flap-sensitive to
            # a single dropped probe).
            entry['lastSent'] = now

            if not self.isDeviceAlive(entry['checkHost'], entry['checkPort']):
                entry['failCount'] += 1
                self.logger.info('[SSDP repeat] Liveness check failed for %s (%s:%s) - %d/%d' %
                                  (usn, entry['checkHost'], entry['checkPort'], entry['failCount'], PacketRelay.LIVENESS_CHECK_MAX_FAILURES))
                if entry['failCount'] >= PacketRelay.LIVENESS_CHECK_MAX_FAILURES:
                    del self.notifyCache[usn]
                    self.logger.info('[SSDP repeat] %s failed liveness check %d times in a row, dropped from cache' %
                                      (usn, entry['failCount']))
                continue

            entry['failCount'] = 0

            data = entry['data']
            addr = entry['addr']
            receivingInterface = entry['receivingInterface']
            ipHeaderLength = entry['ipHeaderLength']
            dstAddr = PacketRelay.SSDP_MCAST_ADDR

            for tx in self.transmitters:
                if receivingInterface == tx['interface']:
                    continue

                transmit = True
                for net in self.ifFilter:
                    (network, netmask) = '/' in net and net.split('/') or (net, '32')
                    if self.onNetwork(entry['addr'], network, self.cidrToNetmask(int(netmask))) and tx['interface'] not in self.ifFilter[net]:
                        transmit = False
                        break
                if not transmit:
                    continue

                if not ((dstAddr == tx['relay']['addr']) and tx['relay']['port'] == PacketRelay.SSDP_MCAST_PORT
                        and (self.oneInterface or not self.onNetwork(addr, tx['addr'], tx['netmask']))):
                    continue

                destMac = self.etherAddrs[dstAddr]
                txData = data
                if tx['interface'] in self.masquerade:
                    txData = txData[:12] + socket.inet_aton(tx['addr']) + txData[16:]

                self.logger.info('[SSDP repeat] Re-announcing %s byte%s cached NOTIFY for %s [ttl %s] to %s:%s via %s/%s' % (
                    len(txData), len(txData) != 1 and 's' or '', usn, entry['ttl'], dstAddr, PacketRelay.SSDP_MCAST_PORT, tx['interface'], tx['addr']))

                try:
                    self.transmitPacket(tx['socket'], tx['mac'], destMac, ipHeaderLength, txData)
                except Exception as e:
                    self.logger.info('[SSDP repeat] Error re-transmitting cached NOTIFY for %s on %s: %s' % (usn, tx['interface'], str(e)))

    MDNS_CACHE_MAX_ENTRIES = 256

    @staticmethod
    def skipDnsName(payload, offset):
        """Return the byte after a DNS name without resolving compression."""
        while offset < len(payload):
            labelLength = payload[offset]
            if labelLength == 0:
                return offset + 1
            if labelLength & 0xc0 == 0xc0:
                return offset + 2 if offset + 1 < len(payload) else None
            if labelLength & 0xc0:
                return None
            offset += labelLength + 1
        return None

    @staticmethod
    def parseMdnsResponse(data, ipHeaderLength):
        """
        Identify a complete positive mDNS service response and the TCP
        endpoint(s) advertised in its SRV records. We intentionally retain
        the original packet rather than attempting to synthesize DNS records:
        the original additional records (PTR/TXT/SRV/A) must stay consistent.
        """
        payload = data[ipHeaderLength+8:]
        if len(payload) < 12:
            return (False, False, False, [])

        flags = struct.unpack('!H', payload[2:4])[0]
        if flags & 0x8000 == 0:
            return (False, False, False, [])

        questionCount, answerCount, authorityCount, additionalCount = struct.unpack('!4H', payload[4:12])
        offset = 12
        for _ in range(questionCount):
            offset = PacketRelay.skipDnsName(payload, offset)
            if offset is None or offset + 4 > len(payload):
                return (False, False, False, [])
            offset += 4

        hasPositiveRecord = False
        hasGoodbyeRecord = False
        servicePorts = []
        for _ in range(answerCount + authorityCount + additionalCount):
            offset = PacketRelay.skipDnsName(payload, offset)
            if offset is None or offset + 10 > len(payload):
                return (False, False, False, [])

            recordType = struct.unpack('!H', payload[offset:offset+2])[0]
            ttl = struct.unpack('!L', payload[offset+4:offset+8])[0]
            dataLength = struct.unpack('!H', payload[offset+8:offset+10])[0]
            recordDataOffset = offset + 10
            if recordDataOffset + dataLength > len(payload):
                return (False, False, False, [])

            if ttl:
                hasPositiveRecord = True
                # SRV RDATA is priority (2), weight (2), port (2), target.
                if recordType == 33 and dataLength >= 6:
                    port = struct.unpack('!H', payload[recordDataOffset+4:recordDataOffset+6])[0]
                    if port:
                        servicePorts.append(port)
            else:
                hasGoodbyeRecord = True
            offset = recordDataOffset + dataLength

        # A standalone all-zero TTL response is an mDNS goodbye. A mixed
        # response can legitimately carry a cache-flush record, so it must
        # not erase the whole device cache.
        return (True, hasPositiveRecord, hasGoodbyeRecord and not hasPositiveRecord, servicePorts)

    def dropMdnsSource(self, sourceAddr):
        removed = 0
        for key in list(self.mdnsCache.keys()):
            if self.mdnsCache[key]['sourceAddr'] == sourceAddr:
                del self.mdnsCache[key]
                removed += 1
        return removed

    def cacheMdnsResponse(self, data, addr, ttl, receivingInterface, ipHeaderLength):
        (isResponse, hasPositiveRecord, isGoodbye, servicePorts) = PacketRelay.parseMdnsResponse(data, ipHeaderLength)
        if not isResponse:
            return

        sourceAddr = socket.inet_ntoa(data[12:16])
        if isGoodbye:
            removed = self.dropMdnsSource(sourceAddr)
            if removed:
                self.logger.info('[mDNS repeat] %s said goodbye, dropped %d cached service response%s' %
                                 (sourceAddr, removed, removed != 1 and 's' or ''))
            return

        # Any positive-TTL answer is worth keeping alive, not just a packet
        # that happens to bundle an SRV record: real devices often split a
        # PTR enumeration burst from the separate SRV/TXT/A packet, and both
        # are legitimate, independently repeatable announcements. When an SRV
        # record IS present we also get a port to use for the liveness probe
        # below; when it isn't, isDeviceAlive() already treats a missing
        # host/port as "can't confirm either way" and skips the probe, same
        # as the SSDP path does for a NOTIFY with no LOCATION header.
        if not hasPositiveRecord:
            return

        checkPort = servicePorts[0] if servicePorts else None

        payload = data[ipHeaderLength+8:]
        key = (sourceAddr, payload)
        now = time.time()
        isNew = key not in self.mdnsCache
        if isNew and len(self.mdnsCache) >= PacketRelay.MDNS_CACHE_MAX_ENTRIES:
            oldestKey = min(self.mdnsCache, key=lambda cachedKey: self.mdnsCache[cachedKey]['lastSeen'])
            del self.mdnsCache[oldestKey]

        self.mdnsCache[key] = {
            'data': data,
            'addr': addr,
            'ttl': ttl,
            'receivingInterface': receivingInterface,
            'ipHeaderLength': ipHeaderLength,
            'sourceAddr': sourceAddr,
            'checkPort': checkPort,
            'lastSent': now,
            'lastSeen': now,
            'failCount': 0,
        }
        if isNew:
            self.logger.info('[mDNS repeat] Caching service response from %s%s, will re-announce every %ds while reachable' %
                             (sourceAddr, checkPort and ':%d' % checkPort or ' (no SRV port - no liveness check)', self.mdnsRepeat))

    def replayMdnsCache(self):
        now = time.time()
        for key in list(self.mdnsCache.keys()):
            entry = self.mdnsCache[key]
            if now - entry['lastSent'] < self.mdnsRepeat:
                continue

            # Do not make a powered-off device linger in remote pickers. A
            # live endpoint keeps its announcement refreshed indefinitely,
            # whereas two failed bounded probes remove it.
            entry['lastSent'] = now
            if not self.isDeviceAlive(entry['sourceAddr'], entry['checkPort']):
                entry['failCount'] += 1
                self.logger.info('[mDNS repeat] Liveness check failed for %s:%s - %d/%d' %
                                 (entry['sourceAddr'], entry['checkPort'], entry['failCount'], PacketRelay.LIVENESS_CHECK_MAX_FAILURES))
                if entry['failCount'] >= PacketRelay.LIVENESS_CHECK_MAX_FAILURES:
                    del self.mdnsCache[key]
                    self.logger.info('[mDNS repeat] %s:%s failed liveness checks, dropped from cache' %
                                     (entry['sourceAddr'], entry['checkPort']))
                continue

            entry['failCount'] = 0
            data = entry['data']
            addr = entry['addr']
            receivingInterface = entry['receivingInterface']
            ipHeaderLength = entry['ipHeaderLength']
            dstAddr = PacketRelay.MDNS_MCAST_ADDR

            for tx in self.transmitters:
                if receivingInterface == tx['interface']:
                    continue

                transmit = True
                for net in self.ifFilter:
                    (network, netmask) = '/' in net and net.split('/') or (net, '32')
                    if self.onNetwork(entry['sourceAddr'], network, self.cidrToNetmask(int(netmask))) and tx['interface'] not in self.ifFilter[net]:
                        transmit = False
                        break
                if not transmit:
                    continue

                if not ((dstAddr == tx['relay']['addr']) and tx['relay']['port'] == PacketRelay.MDNS_MCAST_PORT
                        and (self.oneInterface or not self.onNetwork(addr, tx['addr'], tx['netmask']))):
                    continue

                destMac = self.etherAddrs[dstAddr]
                txData = data
                if tx['interface'] in self.masquerade:
                    txData = txData[:12] + socket.inet_aton(tx['addr']) + txData[16:]

                self.logger.info('[mDNS repeat] Re-announcing %s byte%s cached service response from %s:%s [ttl %s] to %s:%s via %s/%s' % (
                    len(txData), len(txData) != 1 and 's' or '', entry['sourceAddr'], entry['checkPort'], entry['ttl'],
                    dstAddr, PacketRelay.MDNS_MCAST_PORT, tx['interface'], tx['addr']))
                try:
                    self.transmitPacket(tx['socket'], tx['mac'], destMac, ipHeaderLength, txData)
                except Exception as e:
                    self.logger.info('[mDNS repeat] Error re-transmitting cached response from %s:%s on %s: %s' %
                                     (entry['sourceAddr'], entry['checkPort'], tx['interface'], str(e)))

    def loop(self):
        # Record where the most recent SSDP searches came from, to relay unicast answers
        # Note: ideally we'd be more clever and record multiple, but in practice
        #   recording the last one seems to be enough for a 'normal' home SSDP traffic
        #   (devices tend to retry SSDP queries multiple times anyway)
        recentSsdpSearchSrc = {}
        while True:
            if self.remoteAddrs:
                self.connectRemotes()

            if self.ssdpRepeat:
                self.replaySsdpCache()
            if self.mdnsRepeat:
                self.replayMdnsCache()

            additionalListeners = []
            if self.listenSock:
                additionalListeners.append(self.listenSock)
            additionalListeners.extend(self.remoteSockets())

            try:
                (inputready, _, _) = select.select(additionalListeners + self.receivers, [], [], 1)
            except KeyboardInterrupt:
                break
            for s in inputready:
                if s == self.listenSock:
                    (remoteConnection, remoteAddr) = s.accept()
                    if not len(list(filter(lambda addr: PacketRelay.onNetwork(remoteAddr[0], addr[0], PacketRelay.cidrToNetmask(int(addr[1]))), self.listenAddr))):
                        self.logger.info('Refusing connection from %s - not in %s' % (remoteAddr[0], self.listenAddr))
                        remoteConnection.close()
                    else:
                        self.remoteConnections.append(remoteConnection)
                        self.logger.info('REMOTE: Accepted connection from %s' % remoteAddr[0])
                    continue
                else:
                    if s in self.remoteSockets():
                        receivingInterface = 'remote'
                        s.setblocking(1)
                        try:
                            (data, _) = s.recvfrom(2, socket.MSG_WAITALL)
                        except socket.error as e:
                            self.logger.info('REMOTE: Connection closed (%s)' % str(e))
                            self.removeConnection(s)
                            continue

                        if not data:
                            s.close()
                            self.logger.info('REMOTE: Connection closed')
                            self.removeConnection(s)
                            continue

                        size = struct.unpack('!H', data)[0]
                        try:
                            (packet, _) = s.recvfrom(size, socket.MSG_WAITALL)
                        except socket.error as e:
                            self.logger.info('REMOTE: Connection closed (%s)' % str(e))
                            self.removeConnection(s)
                            continue

                        packet = self.aes.decrypt(packet)

                        magic = packet[:len(self.MAGIC)]
                        addr = socket.inet_ntoa(packet[len(self.MAGIC):len(self.MAGIC)+self.IPV4LEN])
                        data = packet[len(self.MAGIC)+self.IPV4LEN:]

                        if magic != self.MAGIC:
                            self.logger.info('REMOTE: Garbage data received, closing connection.')
                            s.close()
                            self.remoteConnection(s)
                            continue

                    else:
                        receivingInterface = 'local'
                        (data, addr) = s.recvfrom(10240)
                        addr = addr[0]

                eighthDataByte = data[8]
                if sys.version_info > (3, 0):
                    eighthDataByte = bytes([data[8]])
                ttl = struct.unpack('B', eighthDataByte)[0]

                if self.ttl:
                    data = data[:8] + struct.pack('B', self.ttl) + data[9:]

                # Use IP checksum information to see if we have already seen this
                # packet, since once we have retransmitted it on an interface
                # we know that we will see it once again on that interface.
                #
                # If we were retransmitting via a UDP socket then we could
                # just disable IP_MULTICAST_LOOP but that won't work as we are
                # using an RAW socket.
                ipChecksum = struct.unpack('!H', data[10:12])[0]
                if ipChecksum in self.recentChecksums:
                    continue

                srcAddr = socket.inet_ntoa(data[12:16])
                dstAddr = socket.inet_ntoa(data[16:20])

                # Compute the length of the IP header so that we can then move past
                # it and delve into the UDP packet to find out what destination port
                # this packet was sent to. The length is encoded in the first least
                # significant nybble of the IP packet and is specified in nybbles.
                firstDataByte = data[0]
                if sys.version_info > (3, 0):
                    firstDataByte = bytes([data[0]])
                ipHeaderLength = (struct.unpack('B', firstDataByte)[0] & 0x0f) * 4
                srcPort = struct.unpack('!H', data[ipHeaderLength+0:ipHeaderLength+2])[0]
                dstPort = struct.unpack('!H', data[ipHeaderLength+2:ipHeaderLength+4])[0]

                # raw sockets cannot be bound to a specific port, so we receive all UDP packets with matching dstAddr
                if receivingInterface == 'local' and not self.match(dstAddr, dstPort):
                    continue

                if self.remoteSockets() and not (receivingInterface == 'remote' and self.noRemoteRelay) and srcAddr != self.ssdpUnicastAddr:
                    packet = self.aes.encrypt(self.MAGIC + socket.inet_aton(addr) + data)
                    for remoteConnection in self.remoteSockets():
                        if remoteConnection == s:
                            continue
                        try:
                            remoteConnection.sendall(struct.pack('!H', len(packet)) + packet)

                            for remote in self.remoteAddrs:
                                if remote['socket'] == remoteConnection and remote['connecting']:
                                    self.logger.info('REMOTE: Connection to %s established' % remote['addr'])
                                    remote['connecting'] = False
                        except socket.error as e:
                            if e.errno == errno.EAGAIN:
                                pass
                            else:
                                self.logger.info('REMOTE: Failed to connect to %s: %s' % (self.remoteAddr, str(e)))
                                self.removeConnection(remoteConnection)
                                continue

                origSrcAddr = srcAddr
                origSrcPort = srcPort
                origDstAddr = dstAddr
                origDstPort = dstPort

                # Record who sent the request
                # FIXME: record more than one?
                destMac = None
                modifiedData = None

                if self.mdnsForceUnicast and dstAddr == PacketRelay.MDNS_MCAST_ADDR and dstPort == PacketRelay.MDNS_MCAST_PORT:
                    data = PacketRelay.mdnsSetUnicastBit(data, ipHeaderLength)

                if self.ssdpUnicastAddr and dstAddr == PacketRelay.SSDP_MCAST_ADDR and dstPort == PacketRelay.SSDP_MCAST_PORT and (re.search(b'M-SEARCH', data) or re.search(b'NOTIFY', data)):
                    recentSsdpSearchSrc = {'addr': srcAddr, 'port': srcPort}
                    self.logger.info('Last SSDP search source: %s:%d' % (srcAddr, srcPort))

                    # Modify the src IP and port to make it look like it comes from us
                    # so as we receive the unicast answers to a well known port (1901)
                    # and can relay them
                    srcAddr = self.ssdpUnicastAddr
                    srcPort = PacketRelay.SSDP_UNICAST_PORT
                    data = PacketRelay.modifyUdpPacket(data, ipHeaderLength, srcAddr=srcAddr, srcPort=srcPort)

                elif self.ssdpUnicastAddr and origDstAddr == self.ssdpUnicastAddr and origDstPort == PacketRelay.SSDP_UNICAST_PORT:
                    if not recentSsdpSearchSrc:
                        # We haven't seen a SSDP multicast request yet
                        continue

                    # Relay the SSDP unicast answer back to the most recent source.
                    # On a network that has heavy SSDP usage, this probably won't
                    # really work as designed: if the unicast reply comes after
                    # another SSDP multicast packet comes in from a different srcAddr
                    # then the reply goes back to the wrong host.
                    dstAddr = recentSsdpSearchSrc['addr']
                    dstPort = recentSsdpSearchSrc['port']
                    self.logger.info('Received SSDP Unicast - received from %s:%d on %s:%d, need to relay to %s:%d' % (origSrcAddr, origSrcPort, origDstAddr, origDstPort, dstAddr, dstPort))
                    data = PacketRelay.modifyUdpPacket(data, ipHeaderLength, dstAddr=dstAddr, dstPort=dstPort)

                    try:
                        destMac = binascii.unhexlify(PacketRelay.unicastIpToMac(dstAddr).replace(':', ''))
                    except Exception as e:
                        self.logger.info('DEBUG: exception while resolving mac of IP %s: %s' % (dstAddr, str(e)))
                        continue

                    # It's possible (though unlikely) we can't resolve the MAC if it's unicast.
                    # In that case, we can't relay the packet.
                    if not destMac:
                        self.logger.info('DEBUG: could not resolve mac for %s' % dstAddr)
                        continue

                # Work out the name of the interface we received the packet on.
                broadcastPacket = False
                if receivingInterface == 'local':
                    for tx in self.transmitters:
                        if (origDstAddr == tx['relay']['addr'] or origDstAddr == tx.get('broadcast')) and origDstPort == tx['relay']['port'] \
                                and self.onNetwork(addr, tx['addr'], tx['netmask']):
                            receivingInterface = tx['interface']
                            broadcastPacket = (origDstAddr == tx['broadcast'])

                if self.ssdpRepeat and origDstAddr == PacketRelay.SSDP_MCAST_ADDR and origDstPort == PacketRelay.SSDP_MCAST_PORT \
                        and not broadcastPacket and re.search(b'NOTIFY \\* HTTP', data):
                    self.cacheSsdpNotify(data, addr, ttl, receivingInterface, ipHeaderLength)

                if self.mdnsRepeat and origDstAddr == PacketRelay.MDNS_MCAST_ADDR and origDstPort == PacketRelay.MDNS_MCAST_PORT \
                        and not broadcastPacket:
                    self.cacheMdnsResponse(data, addr, ttl, receivingInterface, ipHeaderLength)

                for tx in self.transmitters:
                    # Re-transmit on all other interfaces than on the interface that we received this packet from...
                    if receivingInterface == tx['interface']:
                        continue

                    transmit = True
                    for net in self.ifFilter:
                        (network, netmask) = '/' in net and net.split('/') or (net, '32')
                        if self.onNetwork(srcAddr, network, self.cidrToNetmask(int(netmask))) and tx['interface'] not in self.ifFilter[net]:
                            transmit = False
                            break
                    if not transmit:
                        continue

                    if srcAddr == self.ssdpUnicastAddr and not self.onNetwork(srcAddr, tx['addr'], tx['netmask']):
                        continue

                    if broadcastPacket:
                        dstAddr = tx['broadcast']
                        destMac = self.etherAddrs[PacketRelay.BROADCAST]
                        origDstAddr = tx['broadcast']
                        data = data[:16] + socket.inet_aton(tx['broadcast']) + data[20:]

                    if (origDstAddr == tx['relay']['addr'] or origDstAddr == tx.get('broadcast')) and origDstPort == tx['relay']['port'] and (self.oneInterface or not self.onNetwork(addr, tx['addr'], tx['netmask'])):
                        destMac = destMac if destMac else self.etherAddrs[dstAddr]

                        if tx['interface'] in self.masquerade:
                            data = data[:12] + socket.inet_aton(tx['addr']) + data[16:]
                            srcAddr = tx['addr']
                        asSrc = '' if srcAddr == origSrcAddr and srcPort == origSrcPort else ' (as %s:%s)' % (srcAddr, srcPort)
                        self.logger.info('%s%s %s byte%s from %s:%s on %s [ttl %s] to %s:%s via %s/%s%s' % (tx['service'] and '[%s] ' % tx['service'] or '',
                                                                                                          tx['interface'] in self.masquerade and 'Masqueraded' or 'Relayed',
                                                                                                          len(data),
                                                                                                          len(data) != 1 and 's' or '',
                                                                                                          origSrcAddr,
                                                                                                          origSrcPort,
                                                                                                          receivingInterface,
                                                                                                          ttl,
                                                                                                          dstAddr,
                                                                                                          dstPort,
                                                                                                          tx['interface'],
                                                                                                          tx['addr'],
                                                                                                          asSrc))

                        try:
                            self.transmitPacket(tx['socket'], tx['mac'], destMac, ipHeaderLength, data)
                        except Exception as e:
                            if e.errno == errno.ENXIO:
                                try:
                                    (ifname, mac, ip, netmask, broadcast) = self.getInterface(tx['interface'])
                                    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
                                    s.bind((ifname, 0))
                                    tx['mac'] = mac
                                    tx['netmask'] = netmask
                                    tx['addr'] = ip
                                    tx['socket'] = s
                                    self.transmitPacket(tx['socket'], tx['mac'], destMac, ipHeaderLength, data)
                                except Exception as e:
                                    self.logger.info('Error sending packet: %s' % str(e))

    def getInterface(self, interface):
        ifname = None

        # See if we got an interface name.
        if interface in self.nif.interfaces():
            ifname = interface

        # Maybe we got an network/netmask combination?
        elif re.match(r'\A\d+\.\d+\.\d+\.\d+\Z', interface):
            for i in self.nif.interfaces():
                addrs = self.nif.ifaddresses(i)
                if self.nif.AF_INET in addrs:
                    if self.nif.AF_INET in addrs and interface == addrs[self.nif.AF_INET][0]['addr']:
                        ifname = i
                        break

        # Or perhaps we got an IP address?
        elif re.match(r'\A\d+\.\d+\.\d+\.\d+/\d+\Z', interface):
            (network, netmask) = interface.split('/')
            netmask = '.'.join([str((0xffffffff << (32 - int(netmask)) >> i) & 0xff) for i in [24, 16, 8, 0]])

            for i in self.nif.interfaces():
                addrs = self.nif.ifaddresses(i)
                if self.nif.AF_INET in addrs:
                    if self.nif.AF_INET in addrs:
                        ip = addrs[self.nif.AF_INET][0]['addr']
                        if self.onNetwork(ip, network, netmask):
                            ifname = i
                            break

        if not ifname:
            raise IOError('Interface %s does not exist.' % interface)

        try:
            # Here we want to make sure that an interface has an
            # IPv4 address - but if we are running at boot time
            # it might be that we don't yet have an address assigned.
            #
            # --wait doesn't make sense in the situation where we
            # look for an IP# or net/mask combination, of course.
            while True:
                addrs = self.nif.ifaddresses(ifname)
                if self.nif.AF_INET in addrs:
                    break
                if not self.wait:
                    print('Interface %s does not have an IPv4 address assigned.' % ifname)
                    sys.exit(1)
                self.logger.info('Waiting for IPv4 address on %s' % ifname)
                time.sleep(1)

            ip = addrs[self.nif.AF_INET][0]['addr']
            netmask = addrs[self.nif.AF_INET][0]['netmask']

            ipLong = PacketRelay.ip2long(ip)
            netmaskLong = PacketRelay.ip2long(netmask)
            broadcastLong = ipLong | (~netmaskLong & 0xffffffff)
            broadcast = PacketRelay.long2ip(broadcastLong)

            # If we've been given a virtual interface like eth0:0 then
            # netifaces might not be able to detect its MAC address so
            # lets at least try the parent interface and see if we can
            # find a MAC address there.
            if self.nif.AF_LINK not in addrs and ifname.find(':') != -1:
                addrs = self.nif.ifaddresses(ifname[:ifname.find(':')])

            if self.nif.AF_LINK in addrs:
                mac = addrs[self.nif.AF_LINK][0]['addr']
            elif self.allowNonEther:
                mac = '00:00:00:00:00:00'
            else:
                print('Unable to detect MAC address for interface %s.' % ifname)
                sys.exit(1)

            # These functions all return a value in string format, but our
            # only use for a MAC address later is when we concoct a packet
            # to send, and at that point we need as binary data. Lets do
            # that conversion here.
            return (ifname, binascii.unhexlify(mac.replace(':', '')), ip, netmask, broadcast)
        except Exception as e:
            print('Error getting information about interface %s.' % ifname)
            print('Valid interfaces: %s' % ' '.join(self.nif.interfaces()))
            self.logger.info(str(e))
            sys.exit(1)

    @staticmethod
    def isMulticast(ip):
        """
        Is this IP address a multicast address?
        """
        ipLong = PacketRelay.ip2long(ip)
        return ipLong >= PacketRelay.ip2long(PacketRelay.MULTICAST_MIN) and ipLong <= PacketRelay.ip2long(PacketRelay.MULTICAST_MAX)

    @staticmethod
    def isBroadcast(ip):
        """
        Is this IP address a broadcast address?
        """
        return ip == PacketRelay.BROADCAST

    @staticmethod
    def ip2long(ip):
        """
        Given an IP address (or netmask) turn it into an unsigned long.
        """
        packedIP = socket.inet_aton(ip)
        return struct.unpack('!L', packedIP)[0]

    @staticmethod
    def long2ip(ip):
        """
        Given an unsigned long turn it into an IP address
        """
        return socket.inet_ntoa(struct.pack('!I', ip))

    @staticmethod
    def onNetwork(ip, network, netmask):
        """
        Given an IP address and a network/netmask tuple, work out
        if that IP address is on that network.
        """
        ipL = PacketRelay.ip2long(ip)
        networkL = PacketRelay.ip2long(network)
        netmaskL = PacketRelay.ip2long(netmask)
        return (ipL & netmaskL) == (networkL & netmaskL)

    @staticmethod
    def multicastIpToMac(addr):
        # Compute the MAC address that we will use to send
        # packets out to. Multicast MACs are derived from
        # the multicast IP address.
        multicastMac = 0x01005e000000
        multicastMac |= PacketRelay.ip2long(addr) & 0x7fffff
        return struct.pack('!Q', multicastMac)[2:]

    @staticmethod
    def broadcastIpToMac(addr):
        broadcastMac = 0xffffffffffff
        return struct.pack('!Q', broadcastMac)[2:]

    @staticmethod
    def cidrToNetmask(bits):
        return socket.inet_ntoa(struct.pack('!I', (1 << 32) - (1 << (32 - bits))))

class K8sCheck(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(bytes('OK', 'utf-8'))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--interfaces', nargs='+', required=True,
                        help='Relay between these interfaces (minimum 2).')
    parser.add_argument('--noTransmitInterfaces', nargs='+',
                        help='Do not relay packets via these interfaces, listen only.')
    parser.add_argument('--ifFilter',
                        help='JSON file specifying which interface(s) a particular source IP can relay to.')
    parser.add_argument('--ssdpUnicastAddr',
                        help='IP address to listen to SSDP unicast replies, which will be'
                             ' relayed to the IP that sent the SSDP multicast query.')
    parser.add_argument('--ssdpRepeat', type=int, default=0,
                        help='Some SSDP devices only ever send periodic NOTIFY (ssdp:alive) '
                             'announcements and never answer M-SEARCH directly. If set (seconds), '
                             'the relay caches the most recent NOTIFY per device (by USN) and '
                             're-announces it to the other interfaces every N seconds, independent '
                             'of the device\'s own announce interval, while the device endpoint '
                             'continues to answer a bounded liveness check. Try 20-30.')
    parser.add_argument('--mdnsRepeat', type=int, default=60,
                        help='Cache complete mDNS service announcements (such as Google Cast, '
                             'Android TV Remote and AirPlay) and re-announce them every N seconds '
                             'while their SRV endpoint remains reachable. The default 60 is below '
                             'the common 120-second mDNS TTL; set 0 to disable.')
    parser.add_argument('--oneInterface', action='store_true',
                        help='Slightly dangerous: only one interface exists, connected to two networks.')
    parser.add_argument('--relay', nargs='*',
                        help='Relay additional multicast address(es).')
    parser.add_argument('--noMDNS', action='store_true',
                        help='Do not relay mDNS packets.')
    parser.add_argument('--mdnsForceUnicast', action='store_true',
                        help='Force mDNS packets to have the UNICAST-RESPONSE bit set.')
    parser.add_argument('--noSSDP', action='store_true',
                        help='Do not relay SSDP packets.')
    parser.add_argument('--noSonosDiscovery', action='store_true',
                        help='Do not relay broadcast Sonos discovery packets.')
    parser.add_argument('--homebrewNetifaces', action='store_true',
                        help='No longer has any effect: the self-contained, dependency-free '
                             'interface lookup is now always used (netifaces is no longer '
                             'required, or available as an OpenWrt package). Kept only so that '
                             'existing init scripts which pass this flag keep working.')
    parser.add_argument('--ifNameStructLen', type=int, default=None,
                        help='Override the auto-detected ifName struct length (32 on 32-bit '
                             'systems, 40 on 64-bit) used to parse SIOCGIFCONF results. Only '
                             'needed if auto-detection guesses wrong for your target.')
    parser.add_argument('--allowNonEther', action='store_true',
                        help='Allow non-ethernet interfaces to be configured.')
    parser.add_argument('--masquerade', nargs='+',
                        help='Masquerade outbound packets from these interface(s).')
    parser.add_argument('--wait', action='store_true',
                        help='Wait for IPv4 address assignment.')
    parser.add_argument('--ttl', type=int,
                        help='Set TTL on outbound packets.')
    parser.add_argument('--listen', nargs='+',
                        help='Listen for a remote connection from one or more remote addresses A.B.C.D.')
    parser.add_argument('--remote', nargs='+',
                        help='Relay packets to remote multicast-relay(s) on A.B.C.D.')
    parser.add_argument('--remotePort', type=int, default=1900,
                        help='Use this port to listen/connect to.')
    parser.add_argument('--remoteRetry', type=int, default=5,
                        help='If the remote connection is terminated, retry at least N seconds later.')
    parser.add_argument('--noRemoteRelay', action='store_true',
                        help='Only relay packets on local interfaces: don\'t relay packets out of --remote connected relays.')
    parser.add_argument('--aes',
                        help='Encryption key for the connection to the remote multicast-relay.')
    parser.add_argument('--k8sport', type=int,
                        help='Run k8s liveness/readiness server on the given port.')
    parser.add_argument('--foreground', action='store_true',
                        help='Do not background.')
    parser.add_argument('--logfile',
                        help='Save logs to this file.')
    parser.add_argument('--verbose', action='store_true',
                        help='Enable verbose output.')
    args = parser.parse_args()

    if len(args.interfaces) < 2 and not args.oneInterface and not args.listen and not args.remote:
        print('You should specify at least two interfaces to relay between')
        return 1

    if args.remote and args.listen:
        print('Relay role should be either --listen or --remote (or neither) but not both')
        return 1

    if args.ttl and (args.ttl < 0 or args.ttl > 255):
        print('Invalid TTL (must be between 1 and 255)')
        return 1

    if args.ssdpRepeat < 0 or args.mdnsRepeat < 0:
        print('Invalid repeat interval (must be zero or a positive number of seconds)')
        return 1

    if not args.foreground:
        pid = os.fork()
        if pid != 0:
            return 0
        os.setsid()
        os.close(sys.stdin.fileno())

    logger = Logger(args.foreground, args.logfile, args.verbose)

    relays = set()
    if not args.noMDNS:
        relays.add(('%s:%d' % (PacketRelay.MDNS_MCAST_ADDR, PacketRelay.MDNS_MCAST_PORT), 'mDNS'))
    if not args.noSSDP:
        relays.add(('%s:%d' % (PacketRelay.SSDP_MCAST_ADDR, PacketRelay.SSDP_MCAST_PORT), 'SSDP'))
    if not args.noSonosDiscovery:
        relays.add(('%s:%d' % (PacketRelay.BROADCAST, 1900), 'Sonos Discovery'))
        relays.add(('%s:%d' % (PacketRelay.BROADCAST, 6969), 'Sonos Setup Discovery'))

    if args.ssdpUnicastAddr:
        relays.add(('%s:%d' % (args.ssdpUnicastAddr, PacketRelay.SSDP_UNICAST_PORT), 'SSDP Unicast'))

    if args.relay:
        for relay in args.relay:
            relays.add((relay, None))

    packetRelay = PacketRelay(interfaces           = args.interfaces,
                              noTransmitInterfaces = args.noTransmitInterfaces,
                              ifFilter             = args.ifFilter,
                              waitForIP            = args.wait,
                              ttl                  = args.ttl,
                              oneInterface         = args.oneInterface,
                              ifNameStructLen      = args.ifNameStructLen,
                              allowNonEther        = args.allowNonEther,
                              ssdpUnicastAddr      = args.ssdpUnicastAddr,
                              ssdpRepeat           = args.ssdpRepeat,
                              mdnsRepeat           = args.mdnsRepeat,
                              mdnsForceUnicast     = args.mdnsForceUnicast,
                              masquerade           = args.masquerade,
                              listen               = args.listen,
                              remote               = args.remote,
                              remotePort           = args.remotePort,
                              remoteRetry          = args.remoteRetry,
                              noRemoteRelay        = args.noRemoteRelay,
                              aes                  = args.aes,
                              logger               = logger)

    for relay in relays:
        try:
            (addr, port) = relay[0].split(':')
            _ = PacketRelay.ip2long(addr)
            port = int(port)
        except:
            errorMessage = '%s:%s: Expecting --relay A.B.C.D:P, where A.B.C.D is a multicast or broadcast IP address and P is a valid port number' % relay
            if args.foreground:
                print(errorMessage)
            else:
                logger.warning(errorMessage)
            return 1

        if PacketRelay.isMulticast(addr):
            relayType = 'multicast'
        elif PacketRelay.isBroadcast(addr):
            relayType = 'broadcast'
        elif args.ssdpUnicastAddr:
            relayType = 'unicast'
        else:
            errorMessage = 'IP address %s is neither a multicast nor a broadcast address' % addr
            if args.foreground:
                print(errorMessage)
            else:
                logger.warning(errorMessage)
            return 1

        if port < 0 or port > 65535:
            errorMessage = 'UDP port %s out of range' % port
            if args.foreground:
                print(errorMessage)
            else:
                logger.warning(errorMessage)
            return 1

        logger.info('Adding %s relay for %s:%s%s' % (relayType, addr, port, relay[1] and ' (%s)' % relay[1] or ''))
        packetRelay.addListener(addr, port, relay[1])

    if args.k8sport:
        webServer = http.server.HTTPServer(('0.0.0.0', args.k8sport), K8sCheck)
        threading.Thread(target=webServer.serve_forever, daemon=True).start()

    packetRelay.loop()

if __name__ == '__main__':
    sys.exit(main())
