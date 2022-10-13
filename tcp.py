from scapy.all import *

TCP_IN_ICMP = "TCP in ICMP"

class TCPSession(object):
    def __init__(self, ip, dport, max_ttl=64, timeout=3, sport=None, interface=None):
        self.ip = ip
        self.dport = dport
        self.sport = sport
        self._max_ttl = max_ttl
        self._timeout = timeout
        self._interface = interface
        if interface == "any":
            self._interface = None
        self.seq = 0
        self.ack = 0
        ip_id = random.randint(1, 65500)
        if self.sport is None:
            self.sport = random.randint(49152, 65535)
        self.ip_pkt = IP(dst = self.ip, id = ip_id, flags = 'DF', ttl=self._max_ttl)

    def set_iprr(self):
        ip_record_route_option = IPOption_RR(copy_flag=0, length=39, routers=['0.0.0.0'] * 9)
        self.ip_pkt.options.append(ip_record_route_option)

    def iph_length(self):
        """ Returns IP header length in bytes. """
        p = self.ip_pkt.__class__(bytes(self.ip_pkt))
        return p[IP].ihl * 4

    def handshake(self):
        """ Perform TCP handshake. """
        isn = random.getrandbits(32)
        syn = self.ip_pkt / TCP(dport=self.dport, sport=self.sport,
                       flags='S', seq=isn)
        syn_ack = sr1(syn, timeout=self._timeout, verbose=False, iface=self._interface) # send SYN, recv SYNACK
        if syn_ack is None or syn_ack.seq is None:
          return False
        self.seq = syn_ack.ack
        self.ack = syn_ack.seq + 1
        self.ip_pkt.id = self.ip_pkt.id + 1
        del self.ip_pkt.chksum
        ack = self.ip_pkt / TCP(dport=self.dport, sport=self.sport, flags='A', seq=self.seq, ack=self.ack)
        send(ack, verbose=False, iface=self._interface)
        return True

    def sendrecv(self, data, ttl, retries=3):
        """ Sends `data` payload and returns responses. """
        self.ip_pkt.id = self.ip_pkt.id + 1
        self.ip_pkt.ttl = ttl
        del self.ip_pkt.chksum
        req = self.ip_pkt / TCP(dport=self.dport, sport=self.sport,
                       flags='P''A', seq=self.seq, ack=self.ack) / data

        responses = []
        for _ in range(retries):
            # This filter checks for ICMP time exceeded packets or any other packets destined for the session source port.
            # TODO: We don't want to recv() ICMP Time Exceeded packets that are not direct responses to this probe.
            s = AsyncSniffer(filter=f"icmp[0] == 11 or (port {self.sport} and src host {self.ip})", iface=self._interface)
            s.start()
            time.sleep(0.1)
            send(req, verbose=False, iface=self._interface)
            time.sleep(self._timeout)
            responses = s.stop()
            if responses is not None:
                break
        direct_responses = []
        for packet in responses:
            if packet.haslayer(ICMP) and packet.haslayer(TCP_IN_ICMP) and packet[TCP_IN_ICMP].sport != self.sport:
                continue
            # Skip if we accidentally captured any outgoing data
            if packet.haslayer(TCP) and packet[TCP].dport != self.sport:
                continue
            # Skip if we accidentally captured a SYN-ACK retransmission
            if packet.haslayer(TCP) and 'S' in packet[TCP].flags:
                continue
            direct_responses.append(packet)
            self.recv(packet)
        return req, direct_responses

    def recv(self, packet):
        """ Tell TCP Conn that we have received a packet for this connection. """
        if packet.haslayer(ICMP):
            return
        if packet.haslayer(TCP) and 'P' in packet[TCP].flags and \
                packet.seq + len(packet[TCP].payload) > self.ack:
            self.seq = packet.ack
            self.ack = packet.seq + len(packet[TCP].payload)

    def close(self):
        """ Performs FIN handshake. """
        self.ip_pkt.id = self.ip_pkt.id + 1
        self.ip_pkt.ttl = self._max_ttl
        del self.ip_pkt.chksum
        fin = self.ip_pkt / TCP(dport=self.dport, sport=self.sport,
                    flags='F''A', seq=self.seq, ack=self.ack)
        finack = sr1(fin, timeout=3, verbose=False, iface=self._interface)
        if finack is None or not finack.haslayer(TCP):
            return False
        ack = self.ip_pkt / TCP(dport=self.dport, sport=finack.dport, flags='A', seq=finack.ack, ack=finack.seq+1)
        send(ack, verbose=False, iface=self._interface)
        return True

