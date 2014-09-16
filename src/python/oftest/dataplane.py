"""
OpenFlow Test Framework

DataPlane and DataPlanePort classes

Provide the interface to the control the set of ports being used
to stimulate the switch under test.

See the class dataplaneport for more details.  This class wraps
a set of those objects allowing general calls and parsing
configuration.

@todo Add "filters" for matching packets.  Actions supported
for filters should include a callback or a counter
"""

import sys
import os
import socket
import time
import select
import logging
from threading import Thread
from threading import Lock
from threading import Condition
import ofutils
import netutils
from pcap_writer import PcapWriter

have_pypcap = False
OFTEST_SERVER_INTERFACE = ['eth0','eth1','eth2','eth3','eth2.2']
SERVER_1_ADDRESS = '150.225.16.84'
SERVER_2_ADDRESS = '150.225.16.88'
try:
    import pcap
    if hasattr(pcap, "pcap"):
        # the incompatible pylibpcap library masquerades as pcap
        have_pypcap = False ##(jungwoo) because of incompatibility it was disabled.
        ##have_pypcap = True
except:
    pass


def is_valid_ip(ip):
    """Validates IP addresses.
    """
    return is_valid_ipv4(ip) or is_valid_ipv6(ip)

def is_valid_ipv4(ip):
    """Validates IPv4 addresses.
    """
    pattern = re.compile(r"""
        ^
        (?:
        # Dotted variants:
            (?:
            # Decimal 1-255 (no leading 0's)
            [3-9]\d?|2(?:5[0-5]|[0-4]?\d)?|1\d{0,2}
            |
            0x0*[0-9a-f]{1,2}  # Hexadecimal 0x0 - 0xFF (possible leading 0's)
            |
            0+[1-3]?[0-7]{0,2} # Octal 0 - 0377 (possible leading 0's)
            )
            (?:                  # Repeat 0-3 times, separated by a dot
                \.
                (?:
                    [3-9]\d?|2(?:5[0-5]|[0-4]?\d)?|1\d{0,2}
                |
                    0x0*[0-9a-f]{1,2}
                |
                    0+[1-3]?[0-7]{0,2}
                )
            ){0,3}
            |
            0x0*[0-9a-f]{1,8}    # Hexadecimal notation, 0x0 - 0xffffffff
            |
            0+[0-3]?[0-7]{0,10}  # Octal notation, 0 - 037777777777
            |
            # Decimal notation, 1-4294967295:
            429496729[0-5]|42949672[0-8]\d|4294967[01]\d\d|429496[0-6]\d{3}|
            42949[0-5]\d{4}|4294[0-8]\d{5}|429[0-3]\d{6}|42[0-8]\d{7}|
            4[01]\d{8}|[1-3]\d{0,9}|[4-9]\d{0,8}
            )
            $
    """, re.VERBOSE | re.IGNORECASE)
    return pattern.match(ip) is not None

def is_valid_ipv6(ip):
        """Validates IPv6 addresses.
        """
        pattern = re.compile(r"""
            ^
            \s*                         # Leading whitespace
            (?!.*::.*::)                # Only a single whildcard allowed
            (?:(?!:)|:(?=:))            # Colon iff it would be part of a wildcard
            (?:                         # Repeat 6 times:
                [0-9a-f]{0,4}           #   A group of at most four hexadecimal digits
                (?:(?<=::)|(?<!::):)    #   Colon unless preceeded by wildcard
            ){6}                        #
            (?:                         # Either
                [0-9a-f]{0,4}           #   Another group
                (?:(?<=::)|(?<!::):)    #   Colon unless preceeded by wildcard
                [0-9a-f]{0,4}           #   Last group
                (?: (?<=::)             #   Colon iff preceeded by exacly one colon
                 |  (?<!:)              #
                 |  (?<=:) (?<!::) :    #
                 )                      # OR
             |                          #   A v4 address with NO leading zeros
                (?:25[0-4]|2[0-4]\d|1\d\d|[1-9]?\d)
                (?: \.
                    (?:25[0-4]|2[0-4]\d|1\d\d|[1-9]?\d)
                                                                                                                                                                                       ){3}
            )
            \s*                         # Trailing whitespace
            $
        """, re.VERBOSE | re.IGNORECASE | re.DOTALL)
        return pattern.match(ip) is not None

def match_exp_pkt(exp_pkt, pkt):
    """
    Compare the string value of pkt with the string value of exp_pkt,
    and return True iff they are identical.  If the length of exp_pkt is
    less than the minimum Ethernet frame size (60 bytes), then padding
    bytes in pkt are ignored.
    """
    e = str(exp_pkt)
    p = str(pkt)
    print "expected = "+e
    print "received = "+p
    if len(e) < 60:
        p = p[:len(e)]
    return e == p


class DataPlanePort:
    """
    Uses raw sockets to capture and send packets on a network interface.
    """

    RCV_SIZE_DEFAULT = 4096
    ETH_P_ALL = 0x03
    RCV_TIMEOUT = 10000

    def __init__(self, interface_name, udp_port, port_number):
        """
        @param interface_name The name of the physical interface like eth1
        """
        self.interface_name = interface_name
        self.udp_port       = udp_port
        if interface_name in OFTEST_SERVER_INTERFACE:
            try:
                print "---- (1) Connecting to " + interface_name  + " ..."
                self.interface_name = interface_name
                self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,socket.htons(self.ETH_P_ALL))
                self.socket.bind((interface_name, 0))
                netutils.set_promisc(self.socket, interface_name)
                self.socket.settimeout(self.RCV_TIMEOUT)
            except socket.error, e:
                print e
                sys.exit(1)
            print "---- Now connected"

        elif interface_name == SERVER_2_ADDRESS :
            print "---- (2) Connecting to " + interface_name  + " ..."
            try:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
                self.socket.bind(('', self.udp_port))
                self.socket.setblocking(0)
            except socket.error, e:
                print e
                sys.exit(1)
            print "---- Now connected"
        else :
            try:
                self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,socket.htons(self.ETH_P_ALL))
                self.socket.bind((interface_name, 0))
            except socket.error, e:
                print e
                sys.exit(1)
            print "A socket is conneted to "+interface_name
            netutils.set_promisc(self.socket, interface_name)
            self.socket.settimeout(self.RCV_TIMEOUT)

    def __del__(self):
        if self.socket:
            try:
                self.socket.close()
            except socket.error,e:
                print e
                sys.exit(1)
            print self.interface_name+"'s socket is closed"

    def fileno(self):
        """
        Return an integer file descriptor that can be passed to select(2).
        """
        return self.socket.fileno()

    def recv(self):
        """
        Receive a packet from this port.
        @retval (packet data, timestamp)
        """
        if self.udp_port == 0:
            pkt = self.socket.recv(self.RCV_SIZE_DEFAULT)
        else:
            udp_pkt = self.socket.recvfrom(self.RCV_SIZE_DEFAULT)
            pkt = udp_pkt[0]
        return (pkt, time.time())

    def send(self, packet):
        """
        Send a packet out this port.
        @param packet The packet data to send to the port
        @retval The number of bytes sent
        """
        if self.udp_port == 0:
            print "dataplane : sending a packet to "+ self.interface_name
            ret = self.socket.send(packet)
            print "dataplane : sending result = " + str(ret)
            return ret
        else:
            val = 0
            print "dataplane : sending a packet to "+ self.interface_name+ " via "+ str(self.udp_port)
            try:
                val = self.socket.sendto(packet, (self.interface_name, self.udp_port))
            except socket.error, e:
                print e
                sys.exit(1)
            return val

    def down(self):
        """
        Bring the physical link down.
        """
        os.system("ifconfig down %s" % self.interface_name)

    def up(self):
        """
        Bring the physical link up.
        """
        os.system("ifconfig up %s" % self.interface_name)


class DataPlanePortPcap:
    """
    Alternate port implementation using libpcap. This is required for recent
    versions of Linux (such as Linux 3.2 included in Ubuntu 12.04) which
    offload the VLAN tag, so it isn't in the data returned from a read on a raw
    socket. libpcap understands how to read the VLAN tag from the kernel.
    """

    def __init__(self, interface_name, port_number):
        self.pcap = pcap.pcap(interface_name)
        self.pcap.setnonblock()

    def fileno(self):
        return self.pcap.fileno()

    def recv(self):
        (timestamp, pkt) = next(self.pcap)
        return (pkt[:], timestamp)

    def send(self, packet):
        return self.pcap.inject(packet, len(packet))

    def down(self):
        pass

    def up(self):
        pass

class DataPlane(Thread):
    """
    This class provides methods to send and receive packets on the dataplane.
    It uses the DataPlanePort class, or an alternative implementation of that
    interface, to do IO on a particular port. A background thread is used to
    read packets from the dataplane ports and enqueue them to be read by the
    test. The kill() method must be called to shutdown this thread.
    """

    MAX_QUEUE_LEN = 100

    def __init__(self, config=None):
        Thread.__init__(self)

        # dict from port number to port object
        self.ports = {}

        # dict from port number to list of (timestamp, packet)
        self.packet_queues = {}

        # cvar serves double duty as a regular top level lock and
        # as a condition variable
        self.cvar = Condition()

        # Used to wake up the event loop from another thread
        self.waker = ofutils.EventDescriptor()
        self.killed = False

        self.logger = logging.getLogger("dataplane")
        self.pcap_writer = None

        if config is None:
            self.config = {}
        else:
            self.config = config;

        ############################################################
        #
        # The platform/config can provide a custom DataPlanePort class
        # here if you have a custom implementation with different
        # behavior.
        #
        # Set config.dataplane.portclass = MyDataPlanePortClass
        # where MyDataPlanePortClass has the same interface as the class
        # DataPlanePort defined here.
        #
        if "dataplane" in self.config and "portclass" in self.config["dataplane"]:
            self.dppclass = self.config["dataplane"]["portclass"]
        elif have_pypcap:
            self.dppclass = DataPlanePortPcap
        else:
            self.logger.warning("Missing pypcap, VLAN tests may fail. See README for installation instructions.")
            self.dppclass = DataPlanePort

        self.start()

    def run(self):
        """
        Activity function for class
        """
        while not self.killed:
            sockets = [self.waker] + self.ports.values()
            try:
                sel_in, sel_out, sel_err = select.select(sockets, [], [], 1)
            except:
                print sys.exc_info()
                self.logger.error("Select error, exiting")
                break

            with self.cvar:
                for port in sel_in:
                    if port == self.waker:
                        self.waker.wait()
                        continue
                    else:
                        # Enqueue packet
                        pkt, timestamp = port.recv()
                        port_number = port._port_number
                        self.logger.debug("Pkt len %d in on port %d",
                                          len(pkt), port_number)
                        if self.pcap_writer:
                            self.pcap_writer.write(pkt, timestamp, port_number)
                        queue = self.packet_queues[port_number]
                        if len(queue) >= self.MAX_QUEUE_LEN:
                            # Queue full, throw away oldest
                            queue.pop(0)
                            self.logger.debug("Discarding oldest packet to make room")
                        queue.append((pkt, timestamp))
                self.cvar.notify_all()

        self.logger.info("Thread exit")

    def port_add(self, interface_name, udp_port, port_number):
        """
        Add a port to the dataplane
        @param interface_name The name of the physical interface like eth1
        @param port_number The port number used to refer to the port
        Stashes the port number on the created port object.
        """
        self.ports[port_number] = self.dppclass(interface_name, udp_port, port_number)
        self.ports[port_number]._port_number = port_number
        self.packet_queues[port_number] = []
        # Need to wake up event loop to change the sockets being selected on.
        self.waker.notify()

    def send(self, port_number, packet):
        """
        Send a packet to the given port
        @param port_number The port to send the data to
        @param packet Raw packet data to send to port
        """
        self.logger.debug("Sending %d bytes to port %d" %
                          (len(packet), port_number))
        if self.pcap_writer:
            self.pcap_writer.write(packet, time.time(), port_number)
        bytes = self.ports[port_number].send(packet)
        if bytes != len(packet):
            self.logger.error("Unhandled send error, length mismatch %d != %d" %
                     (bytes, len(packet)))
        return bytes

    def oldest_port_number(self):
        """
        Returns the port number with the oldest packet, or
        None if no packets are queued.
        """
        min_port_number = None
        min_time = float('inf')
        for (port_number, queue) in self.packet_queues.items():
            if queue and queue[0][1] < min_time:
                min_time = queue[0][1]
                min_port_number = port_number
        return min_port_number

    # Dequeues and yields packets in the order they were received.
    # Yields (port number, packet, received time).
    # If port_number is not specified yields packets from all ports.
    def packets(self, port_number=None):
        while True:
            rcv_port_number = port_number or self.oldest_port_number()

            if rcv_port_number == None:
                self.logger.debug("Out of packets on all ports")
                break

            queue = self.packet_queues[rcv_port_number]

            if len(queue) == 0:
                self.logger.debug("Out of packets on port %d", rcv_port_number)
                break

            pkt, time = queue.pop(0)
            yield (rcv_port_number, pkt, time)

    def poll(self, port_number=None, timeout=-1, exp_pkt=None):
        """
        Poll one or all dataplane ports for a packet

        If port_number is given, get the oldest packet from that port.
        Otherwise, find the port with the oldest packet and return
        that packet.

        If exp_pkt is true, discard all packets until that one is found

        @param port_number If set, get packet from this port
        @param timeout If positive and no packet is available, block
        until a packet is received or for this many seconds
        @param exp_pkt If not None, look for this packet and ignore any
        others received.  Note that if port_number is None, all packets
        from all ports will be discarded until the exp_pkt is found
        @return The triple port_number, packet, pkt_time where packet
        is received from port_number at time pkt_time.  If a timeout
        occurs, return None, None, None
        """

        if exp_pkt and not port_number:
            self.logger.warn("Dataplane poll with exp_pkt but no port number")

	FILTER=''.join([(len(repr(chr(x)))==3) and chr(x) or '.' for x in range(256)])
        def hex_dump_buffer(src, length=16):
            result = ["\n"]
	    for i in xrange(0, len(src), length):
	        chars = src[i:i+length]
                hex = ' '.join(["%02x" % ord(x) for x in chars])
		printable = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or '.') for x in chars])
		result.append("%04x  %-*s %s\n" % (i, length*3, hex, printable))
	    return ''.join(result)

	def format_packet(pkt):
	    return "Packet length %d \n%s" % (len(str(pkt)),
	                                          hex_dump_buffer(str(pkt)))

        # Retrieve the packet. Returns (port number, packet, time).
        def grab():
            self.logger.debug("Grabbing packet")
            for (rcv_port_number, pkt, time) in self.packets(port_number):
                print "packet received at "+str(time)
                self.logger.debug("Checking packet from port %d", rcv_port_number)
                if not exp_pkt or match_exp_pkt(exp_pkt, pkt):
            	    self.logger.debug("matched %s",format_packet(exp_pkt))
                    return (rcv_port_number, pkt, time)
            self.logger.debug("Did not find packet")
            return None

        with self.cvar:
            ret = ofutils.timed_wait(self.cvar, grab, timeout=timeout)

        if ret != None:
            return ret
        else:
            self.logger.debug("Poll time out, no packet from " + str(port_number))
            return (None, None, None)

    def kill(self):
        """
        Stop the dataplane thread.
        """
        self.killed = True
        self.waker.notify()
        self.join()
        # Explicitly release ports to ensure we don't run out of sockets
        # even if someone keeps holding a reference to the dataplane.
        del self.ports

    def port_down(self, port_number):
        """Brings the specified port down"""
        self.ports[port_number].down()

    def port_up(self, port_number):
        """Brings the specified port up"""
        self.ports[port_number].up()

    def flush(self):
        """
        Drop any queued packets.
        """
        for port_number in self.packet_queues.keys():
            self.packet_queues[port_number] = []

    def start_pcap(self, filename):
        assert(self.pcap_writer == None)
        self.pcap_writer = PcapWriter(filename)

    def stop_pcap(self):
        if self.pcap_writer:
            self.pcap_writer.close()
            self.pcap_writer = None
