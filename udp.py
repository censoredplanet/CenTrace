from operator import truediv
from socket import timeout
from scapy.all import *

UDP_IN_ICMP = "UDP in ICMP"

class UDPSession(object):
    def __init__(self, ip, dport, max_ttl=64, timeout=3, sport=None, interface=None):
        self.ip = ip
        self.dport = dport
        self.sport = sport
        self._max_ttl = max_ttl
        self._timeout = timeout
        self._interface = interface
        if interface == "any":
            self._interface = None
        ip_id = random.randint(1, 65500)
        if self.sport is None:
            self.sport = random.randint(49152, 65535)
        self.ip_pkt = IP(dst = self.ip, id = ip_id, flags = 'DF', ttl=self._max_ttl)
    
    #Calling this a handshake, but it's not really
    def handshake(self, hostname):
        self.ip_pkt.id = self.ip_pkt.id + 1
        self.ip_pkt.ttl = self._max_ttl
        del self.ip_pkt.chksum
        req = self.ip_pkt / UDP(dport=self.dport, sport=self.sport) / DNS(rd=1, qd=DNSQR(qname=hostname))

        answer = sr1(req, verbose=False, timeout=self._timeout)
        if answer is not None:
            return True
        return False

    def set_iprr(self):
        ip_record_route_option = IPOption_RR(copy_flag=0, length=39, routers=['0.0.0.0'] * 9)
        self.ip_pkt.options.append(ip_record_route_option)
    
    def iph_length(self):
        """ Returns IP header length in bytes. """
        p = self.ip_pkt.__class__(bytes(self.ip_pkt))
        return p[IP].ihl * 4
    

    def sendrecv(self, data, ttl, retries=3):
        """ Sends `data` payload and returns responses. """
        self.ip_pkt.id = self.ip_pkt.id + 1
        self.ip_pkt.ttl = ttl
        del self.ip_pkt.chksum
        req = self.ip_pkt / UDP(dport=self.dport, sport=self.sport) / data

        responses = []
        for _ in range(retries):
            # This filter checks for ICMP time exceeded packets or any other packets destined for the session source port.
            # TODO: We don't want to recv() ICMP Time Exceeded packets that are not direct responses to this probe.
            s = AsyncSniffer(filter=f"icmp[0] == 11 or (port {self.sport} and not dst host {self.ip})")
            s.start()
            time.sleep(0.1)
            send(req, verbose=False)
            time.sleep(self._timeout)
            responses = s.stop()
            if responses is not None:
                break
        direct_responses = []
        for packet in responses:
            if packet.haslayer(ICMP) and packet.haslayer(UDP_IN_ICMP) and packet[UDP_IN_ICMP].sport != self.sport:
                continue
            direct_responses.append(packet)
        return req, direct_responses