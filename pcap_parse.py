"""
Usage: 

Analyzes pcaps from `probe.py` to identify potential middlebox blocking devices. 
"""
import os
import errno
import sys
import argparse
import glob
import csv
import json
import random
import itertools

from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

from scapy.all import *
import logging

import asn


load_layer("http")
load_layer("tls")

class CensorshipType(Enum):
    pass

class ApplicationResponse(CensorshipType):
    HTTP = "HTTP"
    TLS = "TLS"

class NetworkResponse(CensorshipType):
    RST = "RST"
    FIN = "FIN"
    ACK = "ACK"

class ErrorResponse(CensorshipType):
    HANDSHAKE_TIMEOUT = "HANDSHAKE_TIMEOUT"
    TIMEOUT = "TIMEOUT"
    UNKNOWN = "UNKNOWN"

class OtherResponse(Enum):
    ICMP_OTHER = "ICMP_OTHER"

class ICMPResponse(Enum):
    TTL = "ICMP_TTL"

# This determines the precedence of response types when identified in a single packet.
# That is, if a packet contains (ICMP, ACK, TLS) layers, we consider that an
# ICMP response. If a packet contains only (ACK, TLS) layers, we consider that a valid
# TLS response.
PACKET_RESPONSE_PRECEDENCE = (*list(ICMPResponse), *list(ApplicationResponse), *list(NetworkResponse))

# Determines precedence of response types when identified as responses of a single probe.
PROBE_RESPONSE_PRECEDENCE = (NetworkResponse.RST, NetworkResponse.FIN, *list(ApplicationResponse), NetworkResponse.ACK, ICMPResponse.TTL)

TCP_IN_ICMP = "TCP in ICMP"


def _get_response_type(packet):
    layers = set()
    if packet.haslayer("HTTPResponse"):
        layers.add(ApplicationResponse.HTTP)
    if packet.haslayer("TLS"):
        layers.add(ApplicationResponse.TLS)
    if packet.haslayer("ICMP"):
        if packet[ICMP].type == 11:
            layers.add(ICMPResponse.TTL)
        else:
            layers.add(OtherResponse.ICMP_OTHER)
    if packet.haslayer("TCP"):
        if 'R' in packet[TCP].flags:
            layers.add(NetworkResponse.RST)
        elif 'F' in packet[TCP].flags:
            layers.add(NetworkResponse.FIN)
        elif 'A' in packet[TCP].flags:
            layers.add(NetworkResponse.ACK)

    for response in PACKET_RESPONSE_PRECEDENCE:
        if response in layers:
            return response
    return ErrorResponse.UNKNOWN

class ResponseCode(Enum):
    # Censored probe's terminating TTL is past control probe
    TERMINATING_TTL_PAST_CONTROL = "TERMINATING_TTL_PAST_CONTROL"
    # Censored probe's terminating TTL is same as control probe, but responses differ
    ENDPOINT_FIREWALL = "ENDPOINT_FIREWALL"
    # Identified middlebox IP is same as endpoint server
    NAT_FIREWALL = "NAT_FIREWALL"
    # Control probe has ICMP response at censored probe's terminating TTL
    CAN_IDENTIFY_SERVER = "CAN_IDENTIFY_SERVER"
    # Control probe has no response at censored probe's terminating TTL, but there are
    # surrounding TTL probes
    CAN_IDENTIFY_POSSIBLE_SERVER = "CAN_IDENTIFY_POSSIBLE_SERVER"
    # Control probe has no probe or response at censored probe's terminating TTL, including in surrounding TTL probes
    NO_CORRESPONDING_RESPONSE = "NO_CORRESPONDING_RESPONSE"
    # Payload from censored and control probes are the same and comes from the same hop.
    NO_OBSERVED_CENSORSHIP = "NO_OBSERVED_CENSORSHIP"
    # Either control probe or censored probe seems to have been corrupted or terminated early.
    TERMINATED_EARLY = "PROBE_TERMINATED_EARLY"
    UNKNOWN = "UNKNOWN"
    ERROR = "ERROR"

@dataclass
class ProbeAnalysis:
    response_code: ResponseCode
    details: str = ""
    censored_terminating_ttl: Optional[int] = None
    uncensored_terminating_ttl: Optional[int] = None
    censorship_type: CensorshipType = ErrorResponse.UNKNOWN
    control_response_type: CensorshipType = ErrorResponse.UNKNOWN
    payloads_differ: bool = True
    censored_payload: str = ""
    control_payload: str = ""
    middlebox: str = ""
    middlebox_before: str = ""
    middlebox_after: str = ""
    # possible_middleboxes: List[str] = field(default_factory=list)
    on_path: bool = False
    rrs_censored: Dict[int, Set[str]] = field(default_factory=dict)
    rrs_uncensored: Dict[int, Set[str]] = field(default_factory=dict)
    all_iph: List[Set[str]] = field(default_factory=list)
    middlebox_iph: Optional[Set[str]] = None
    censored_terminating_features: Optional[Tuple[str]] = None
    control_terminating_features: Optional[Tuple[str]] = None

    def ttl_diff(self):
        if self.censored_terminating_ttl is None or self.uncensored_terminating_ttl is None:
            return None
        return self.censored_terminating_ttl - self.uncensored_terminating_ttl

    @staticmethod
    def from_probes(censored, uncensored):
        payloads_differ, censored_payload, control_payload = _probes_differ(censored, uncensored)
        return ProbeAnalysis(ResponseCode.UNKNOWN,
                censored_terminating_ttl = censored.first_terminating_response(),
                uncensored_terminating_ttl = uncensored.first_terminating_response(),
                censorship_type = censored.response_type(),
                control_response_type = uncensored.response_type(),
                payloads_differ = payloads_differ,
                censored_payload = censored_payload,
                control_payload = control_payload,
                on_path = censored.on_path_injection(),
                rrs_censored = censored.rrs,
                rrs_uncensored = uncensored.rrs,
                all_iph = uncensored.all_ip_header_diff(),
                censored_terminating_features = censored.terminating_response_features(),
                control_terminating_features = uncensored.terminating_response_features())


def analysis(censored_probes, uncensored_probes, search_range=1):
    """
    censored_probes, uncensored_probes are Probes objects to compare.
    search_range: will search TTL -/+ search_range of the terminating TTL in the uncensored probe.
    """
    if censored_probes.terminated_early() or  uncensored_probes.terminated_early():
        return ProbeAnalysis(ResponseCode.TERMINATED_EARLY)
    result = ProbeAnalysis.from_probes(censored_probes, uncensored_probes)
    if result.censored_terminating_ttl is None:
        result.censored_terminating_ttl = censored_probes.last_response() + 1 # one past the last response they get
    if result.censored_terminating_ttl > max(uncensored_probes.ttls()) + 1:
        result.response_code = ResponseCode.TERMINATING_TTL_PAST_CONTROL
        return result

    if result.ttl_diff() == 0 and not result.payloads_differ:
        result.response_code = ResponseCode.NO_OBSERVED_CENSORSHIP
        return result
    if result.censored_terminating_ttl == result.uncensored_terminating_ttl:
        result.response_code = ResponseCode.ENDPOINT_FIREWALL
        return result
    response_details = ""
    if not uncensored_probes.has(result.censored_terminating_ttl):
        response_details += f"Uncensored probe's does not have probe at TTL {result.censored_terminating_ttl}\n"
    else:
        ttl = result.censored_terminating_ttl
        corresponding_probe = uncensored_probes.get(ttl)
        if result.censorship_type == ErrorResponse.TIMEOUT:
            while corresponding_probe.response_type() == ErrorResponse.TIMEOUT:
                ttl += 1
                corresponding_probe = uncensored_probes.get(ttl)
        if len(corresponding_probe.responses) == 0:
            response_details += f"Corresponding uncensored probe has no response.\n"
        for response in corresponding_probe.responses:
            result.middlebox = response[IP].src
            result.middlebox_iph = corresponding_probe.get_ip_header_diff()
    candidate_responses = []
    t_ttl = result.censored_terminating_ttl
    ip_before = ""
    ip_after = ""
    if uncensored_probes.has(t_ttl-1):
        if len(uncensored_probes.get(t_ttl-1).responses) > 0:
            ip_before = uncensored_probes.get(t_ttl-1).responses[0][IP].src
    if uncensored_probes.has(t_ttl+1):
        if len(uncensored_probes.get(t_ttl+1).responses) > 0:
            ip_after = uncensored_probes.get(t_ttl+1).responses[0][IP].src
    response_details += f"Middlebox IP: {result.middlebox}, Other candidates: {ip_before}, {ip_after}"
    result.middlebox_before = ip_before
    result.middlebox_after = ip_after
    result.details = response_details
    if len(result.middlebox) > 0:
        result.response_code = ResponseCode.CAN_IDENTIFY_SERVER
        if result.middlebox == censored_probes.server_ip:
            result.response_code = ResponseCode.NAT_FIREWALL
    elif len(result.middlebox_before) > 0 or len(result.middlebox_after) > 0:
        result.response_code = ResponseCode.CAN_IDENTIFY_POSSIBLE_SERVER
    else:
        result.response_code = ResponseCode.NO_CORRESPONDING_RESPONSE
    return result
    
# Object representing many samples of TTL probes to the same server & keyword
class ProbeSet(object):
    def __init__(self, probes_list):
        self.probes = probes_list
        self.server_ip = probes_list[0].server_ip
        self.keyword = probes_list[0].keyword
        self.censored = probes_list[0].censored

    @staticmethod
    def from_pcaps(filenames):
        probes_list = []
        for filename in filenames:
            try:
                probes_list.append(Probes.from_pcap(filename))
            except:
                continue
        if len(probes_list) == 0:
            return None
        return ProbeSet(probes_list)

    # From distribution of TTL Probes, construct new Probes with most likely responses
    def get_likeliest_path(self):
        by_hop = {}
        for probe in self.probes:
            for ttl in probe.ttls():
                if ttl not in by_hop:
                    by_hop[ttl] = {}
                response_ip = probe.get(ttl).response_ip()
                response_type = probe.get(ttl).response_type()
                if (response_ip, response_type) not in by_hop[ttl]:
                    by_hop[ttl][(response_ip, response_type)] = []
                by_hop[ttl][(response_ip, response_type)].append(probe.get(ttl))
        raw_probes = []
        for ttl, datum in by_hop.items():
            most_common = max(datum.keys(), key=lambda k: len(datum[k]))
            raw_probes.append(random.choice(datum[most_common]))
        return Probes(raw_probes, self.server_ip, self.keyword, self.censored)

    # From distribution of TTL Probes, choose one that has the most common terminating TTL
    def get_likeliest_path_by_ttl(self):
        most_common_ttl = Counter([p.first_terminating_response() for p in self.probes]).most_common(1)[0][0]
        return random.choice([p for p in self.probes if p.first_terminating_response() == most_common_ttl])

# Object representing a bunch of TTL probes (starting from 0, counting up)
class Probes(object):
    def __init__(self, probes, server_ip, keyword, censored):
        self.probes = {}
        self.rrs = {}
        for probe in probes:
            self.probes[probe.ttl()] = probe
            self.rrs = _process_rr(self.rrs, probe.get_rr())
        self.server_ip = server_ip
        self.keyword = keyword
        self.censored = censored

    def ttls(self):
        return sorted(list(self.probes.keys()))

    def get(self, ttl):
        return self.probes[ttl]

    def has(self, ttl):
        return ttl in self.ttls()

    def iter(self):
        for ttl in sorted(self.ttls()):
            yield self.probes[ttl]

    def first_terminating_response(self):
        for probe in self.iter():
            if probe.has_terminating_response():
                return probe.ttl()
        return None

    def terminating_response_features(self):
        ttl = self.first_terminating_response()
        if ttl is None:
            return None
        response = self.get(ttl).response_packet()
        if response is None:
            return None
        return (str(response[IP].flags),
                str(response[IP].tos),
                str(response[IP].ttl),
                str(response[IP].id),
                str(response[TCP].window),
                str(response[TCP].options),
                str(response[TCP].flags))

    def response_type(self):
        if self.terminated_early():
            return ErrorResponse.UNKNOWN
        term = self.first_terminating_response()
        if term is None:
            return ErrorResponse.TIMEOUT
        return self.get(term).response_type()

    def on_path_injection(self):
        term = self.first_terminating_response()
        if term is None:
            return False
        return self.get(term).on_path_injection()

    def last_response(self):
        for ttl in self.ttls()[::-1]:
            if len(self.probes[ttl].responses) > 0:
                return ttl

    def terminated_early(self):
        return self.first_terminating_response() is None and max(self.ttls()) != 63

    def all_ip_header_diff(self):
        return {i: self.get(i).get_ip_header_diff() for i in self.ttls()}

    @staticmethod
    def from_pcap(filename):
        if not os.path.exists(filename):
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), filename)
        parts = os.path.basename(filename).split("_")
        ip, censored, tested = parts[:3]
        tested = tested.removesuffix(".pcap")
        packet_handle = PcapReader(filename)
        packets = rdpcap(filename)
        probes = {}
        for packet in packets:
            if Probe._is_probe(packet):
                probe = Probe.from_packets(packet, packets)
                if probe.ttl() in probes: continue
                probes[probe.ttl()] = probe
        packet_handle.close()
        sport = probes[min(probes.keys())].sport()
        # Fill in missing probes... were any handshake timeouts?
        # Assuming increasing port # per probe by 1
        for ttl in range(min(probes.keys()), max(probes.keys())):
            if ttl not in probes:
                probes[ttl] = Probe.from_handshake(sport, ttl, packets)
            sport += 1
        return Probes(list(probes.values()), ip, tested, censored == tested)


#TODO: This function currently only compares known header values and does not look for additional headers. 
#TODO: (IMP) Check for additional headers added to the packet similar to tracebox. 
def compare_quoted_packets(req, res):
    quoted_differences = set()
    #res[ICMP].show()
    if res[ICMP].haslayer("IP in ICMP"):
        ip_in_icmp = "IP in ICMP"
        if res[ICMP][ip_in_icmp].version != req[IP].version:
            quoted_differences.add("IP::Version")
        if res[ICMP][ip_in_icmp].ihl != req[IP].ihl:
            quoted_differences.add("IP::IHL")
        if res[ICMP][ip_in_icmp].tos != req[IP].tos:
            quoted_differences.add("IP::TOS")
        if res[ICMP][ip_in_icmp].len != req[IP].len:
            quoted_differences.add("IP::Length")
        if res[ICMP][ip_in_icmp].tos != req[IP].tos:
            quoted_differences.add("IP::TOS")
        if res[ICMP][ip_in_icmp].flags != req[IP].flags:
            quoted_differences.add("IP::Flags")
        if res[ICMP][ip_in_icmp].frag != req[IP].frag:
            quoted_differences.add("IP::Fragment")
        if res[ICMP][ip_in_icmp].ttl != req[IP].ttl:
            quoted_differences.add("IP::TTL")
        if res[ICMP][ip_in_icmp].proto != req[IP].proto:
            quoted_differences.add("IP::PROTOCOL")
        if res[ICMP][ip_in_icmp].chksum != req[IP].chksum:
            quoted_differences.add("IP::CheckSum")
        if res[ICMP][ip_in_icmp].ihl > 5:
            if res[ICMP][ip_in_icmp].options != req[IP].options:
                quoted_differences.add("IP::Options")
        if res[ICMP][ip_in_icmp].haslayer("TCP in ICMP"):
            tcp_in_icmp = "TCP in ICMP"
            if res[ICMP][ip_in_icmp][tcp_in_icmp].sport != req[IP][TCP].sport:
                quoted_differences.add("TCP::SourcePort")
            if res[ICMP][ip_in_icmp][tcp_in_icmp].dport != req[IP][TCP].dport:
                quoted_differences.add("TCP::DestPort")
            if res[ICMP][ip_in_icmp][tcp_in_icmp].seq != req[IP][TCP].seq:
                quoted_differences.add("TCP::Seq")
            if res[ICMP][ip_in_icmp][tcp_in_icmp].ack == 0:
                quoted_differences.add("Partial TCP")
            else:
                if res[ICMP][ip_in_icmp][tcp_in_icmp].ack != req[IP][TCP].ack:
                    quoted_differences.add("TCP::Ack")
                if res[ICMP][ip_in_icmp][tcp_in_icmp].dataofs != req[IP][TCP].dataofs:
                    quoted_differences.add("TCP::DataOffset")
                if res[ICMP][ip_in_icmp][tcp_in_icmp].reserved != req[IP][TCP].reserved:
                    quoted_differences.add("TCP::Reserved")
                if res[ICMP][ip_in_icmp][tcp_in_icmp].flags != req[IP][TCP].flags:
                    quoted_differences.add("TCP::Flags")
                if res[ICMP][ip_in_icmp][tcp_in_icmp].window != req[IP][TCP].window:
                    quoted_differences.add("TCP::Window")
                if res[ICMP][ip_in_icmp][tcp_in_icmp].urgptr != req[IP][TCP].urgptr:
                    quoted_differences.add("TCP::UrgPtr")
                if res[ICMP][ip_in_icmp][tcp_in_icmp].haslayer("TLS"):
                    if res[ICMP][ip_in_icmp][tcp_in_icmp][TLS].type != req[IP][TCP][TLS].type:
                        quoted_differences.add("TLS::Type")
                    if res[ICMP][ip_in_icmp][tcp_in_icmp][TLS].version != req[IP][TCP][TLS].version:
                        quoted_differences.add("TLS::Version")
                    if res[ICMP][ip_in_icmp][tcp_in_icmp][TLS].len != req[IP][TCP][TLS].len:
                        quoted_differences.add("TLS::Length")
                    if res[ICMP][ip_in_icmp][tcp_in_icmp][TLS].iv != req[IP][TCP][TLS].iv:
                        quoted_differences.add("TLS::IV")
                elif res[ICMP][ip_in_icmp][tcp_in_icmp].haslayer("HTTPResponse"):
                    if res[ICMP][ip_in_icmp][tcp_in_icmp]["HTTPResponse"] != req[IP][TCP]["HTTPResponse"]:
                        quoted_differences.add("HTTP")
                else:
                    quoted_differences.add("No quoted App. data")
        else:
            quoted_differences.add("No Quoted TCP")
    else:
        quoted_differences.add("No Quoted Packets")
    return quoted_differences


class Probe(object):
    def __init__(self, packet, all_packets, ttl=None, sport=None, messy=False):
        self.raw_packet = packet
        self._sport = sport
        if self._sport is None:
            self._sport = self.raw_packet[TCP].sport
        self._ttl = ttl
        if self._ttl is None:
            self._ttl = self.raw_packet[IP].ttl
        self.responses = []
        self.retries = [self]
        self._all_packets = all_packets
        self.messy = messy

    def sport(self):
        return self._sport

    def add_response(self, packet):
        self.responses.append(packet)

    def add_retries(self, probes):
        self.retries += probes

    def num_retries(self):
        return (len(self.retries))

    def ttl(self):
        return self._ttl

    def get_rr(self):
        for response in self.responses:
            if _get_response_type(response) == ICMPResponse.TTL:
                if not response.haslayer("IP Option Record Route"):
                    return None
                return response["IP Option Record Route"].routers
        return None

    def get_ip_header_diff(self):
        for response in self.responses:
            if _get_response_type(response) == ICMPResponse.TTL:
                return compare_quoted_packets(self.raw_packet, response)
        return None

    def payload(self):
        pkts = []
        for response in self.responses:
            if isinstance(_get_response_type(response), ApplicationResponse):
                if response.haslayer("TLS"):
                    pkts = sniff(offline=self._all_packets, session=TLSSession)
                else:
                    pkts = sniff(offline=self._all_packets, session=TCPSession)
        server_hello = None
        server_cert = None
        for pkt in pkts:
            if pkt.haslayer("HTTP Response"):
                if not hasattr(pkt.payload, "load"):
                    return None
                return (pkt.payload.load)
            if pkt.haslayer("TLS Handshake - Server Hello") and server_hello is None:
                server_hello = "|".join([str(pkt["TLS Handshake - Server Hello"].version), 
                    str(pkt["TLS Handshake - Server Hello"].cipher)])
            if pkt.haslayer("TLS Handshake - Certificate") and server_cert is None:
                server_cert = bytes(pkt["TLS Handshake - Certificate"])
        if server_hello is not None or server_cert is not None:
            return "|".join([str(server_hello), str(server_cert)])
        return None

    def summary(self):
        response_type = self.response_type()
        if isinstance(response_type, ErrorResponse):
            return [response_type.value]
        resp = []
        for response in self.responses:
            response_type = _get_response_type(response).value
            if response_type == "HTTP":
                response_type += f" {response[HTTPResponse].Status_Code.decode('utf-8')}"
            resp.append(f"{response[IP].src} {response_type}")
        return resp

    def on_path_injection(self):
        types = set([_get_response_type(r) for r in self.responses])
        if ICMPResponse.TTL in types and isinstance(self.response_type(), CensorshipType):
            return True
        return False

    def response_packet(self):
        primary_rtype = self.response_type()
        if isinstance(self.response_type(), ErrorResponse):
            return None
        for r in self.responses:
            rtype = _get_response_type(r)
            if rtype == primary_rtype:
                return r
        return None

    def response_ip(self):
        if isinstance(self.response_type(), ErrorResponse):
            return None
        return self.response_packet()[IP].src

    def response_type(self):
        if len(self._all_packets) == 1:
            # If there's only one SYN packet sent, that means we timed out in handshake.
            return ErrorResponse.HANDSHAKE_TIMEOUT
        if self.raw_packet is None:
            return ErrorResponse.UNKNOWN
        if len(self.responses) == 0:
            return ErrorResponse.TIMEOUT
        types = [_get_response_type(r) for r in self.responses]
        for response in PROBE_RESPONSE_PRECEDENCE:
            if response in types:
                return response
        return ErrorResponse.UNKNOWN

    def has_terminating_response(self):
        for response in self.responses:
            if isinstance(_get_response_type(response), CensorshipType): #  in ["TLS", "HTTP", "RST", "ACK", "FIN"]:
                return True
        return False

    @staticmethod
    def _is_probe(packet):
      if packet.haslayer(ICMP):
          return False
      # Probe packets are Push packets, and have an application destination port.
      return packet.haslayer(TCP) and 'P' in packet[TCP].flags and packet[TCP].dport < 1024

    @staticmethod
    def from_handshake(port, ttl, packets):
        packets = [packet for packet in packets if packet.haslayer("TCP") and \
                                port in [packet[TCP].sport, packet[TCP].dport]]
        return Probe(None, packets, ttl=ttl, sport=port)

    @staticmethod
    def from_packets(probe_packet, packets):
        probes = []
        for packet in packets:
            # Add any ICMP responses
            if packet.haslayer(ICMP) and packet.haslayer(TCP_IN_ICMP) and packet[TCP_IN_ICMP].sport == probe_packet[TCP].sport:
                if probes: probes[-1].add_response(packet)
                continue
            if packet.haslayer(TCP):
                # If we found current probe packet, add all packets with that sport to the probes
                if packet[TCP].sport == probe_packet[TCP].sport and Probe._is_probe(packet):
                    session_packets = [p for p in packets if (p.haslayer("TCP") or p.haslayer("TCP in ICMP")) and \
                                                             (p.sport == packet[TCP].sport or p.dport == packet[TCP].sport)]
                    probes.append(Probe(packet, session_packets))
                if probe_packet[TCP].sport in [packet[TCP].dport, packet[TCP].sport]:
                    if packet[TCP].dport == probe_packet[TCP].sport:
                        if 'R' in packet[TCP].flags or ('A' in packet[TCP].flags and packet[TCP].ack > probe_packet[TCP].seq + 1):
                            if probes: probes[-1].add_response(packet)
                    # Break (stop processing) when we reach FIN.
                    if 'F' in packet[TCP].flags:
                        break
        if len(probes) == 0:
            # If we reach here, that likely means that there was another probe with overlapping source port.
            # The resulting probe may be inaccurately recorded.
            session_packet = [p for p in packets if (p.haslayer("TCP") or p.haslayer("TCP in ICMP")) and \
                                                     (p.sport == packet[TCP].sport or p.dport == packet[TCP].sport)]
            return Probe(packet, session_packet, messy=True)
        probes[-1].add_retries(probes[:-1])
        return probes[-1]

def _process_rr(all_rrs, rr):
    if rr is None:
        return all_rrs
    for i in range(len(rr)):
        if rr[i] == "0.0.0.0":
            continue
        if i not in all_rrs:
            all_rrs[i] = set()
        all_rrs[i].add(rr[i])
    return all_rrs

def main_compare_files(censored_filename, uncensored_filename, stdout):
    probes1 = Probes.from_pcap(censored_filename)
    probes2 = Probes.from_pcap(uncensored_filename)
    return main_compare(probes1, probes2, stdout)

def main_compare(censored_probes, uncensored_probes, stdout):
    width = len("###.###.###.### ICMP_TTL")
    try:
        probes1 = censored_probes
        probes2 = uncensored_probes
        ttls = sorted(list(set(probes1.ttls()) | set(probes2.ttls())))
        for ttl in ttls:
            responses1, responses2 = [], []
            if probes1.has(ttl):
                responses1 = probes1.get(ttl).summary()
            if probes2.has(ttl):
                responses2 = probes2.get(ttl).summary()
            lines = itertools.zip_longest(responses1, responses2)
            ttlstr = str(ttl)
            for r1, r2 in lines:
                if r1 == None: r1 = ""
                if r2 == None: r2 = ""
                stdout.write(f"{str.rjust(ttlstr, 2)} | {str.center(r1, width)} | {str.center(r2, width)}\n")
                ttlstr = ""
        result = analysis(probes1, probes2)
        result.rrs_censored = probes1.rrs
        result.rrs_uncensored = probes2.rrs
    except Exception as e:
        return ProbeAnalysis(ResponseCode.ERROR)
    stdout.write(result.response_code.value + "\n")
    if result.on_path:
        stdout.write("Detected possible on-path injection\n")
    stdout.write(result.details)
    return result

def _abbreviate(payload, maxlen=100):
    if payload is None:
        return None
    return payload[:maxlen]

def _probes_differ(probe1, probe2):
    # If TTL varies very slightly but response payloads are the same, we still
    # consider those two probes to have resulted in the same response.
    terminating_ttl1 = probe1.first_terminating_response()
    terminating_ttl2 = probe2.first_terminating_response()
    if (terminating_ttl1 is None) ^ (terminating_ttl2 is None):
        return True, None, None
    ttlprobe1 = probe1.get(terminating_ttl1)
    ttlprobe2 = probe2.get(terminating_ttl2)
    if ttlprobe1.response_type() != ttlprobe2.response_type():
        return True, ttlprobe1.response_type(), ttlprobe2.response_type()
    payload1 = ttlprobe1.payload()
    payload2 = ttlprobe2.payload()
    if payload1 == payload2:
        return False, _abbreviate(payload1), _abbreviate(payload2)
    return True, _abbreviate(payload1), _abbreviate(payload2)


def main_file(filename, stdout):
    probes = Probes.from_pcap(filename)
    for ttl, probe in probes.items():
        stdout.write("\n".join([f"{ttl}: {p}" for p in probe.summary()]) + "\n")

def _set_default(obj):
    if isinstance(obj, set):
        return list(obj)
    raise TypeError

def probes_from_cache(cached):
    parsed = set()
    if cached is None:
        return parsed
    with open(cached, "r") as f:
        csvreader = csv.reader(f)
        for row in csvreader:
            ip, keyword, _, _, _, _, _ = row
            parsed.add((ip, keyword))
    return parsed

def main_dir(dirname, prefix, summary, stdout, cached=None):
    old_stdout = stdout
    csvwriter = csv.writer(old_stdout)
    parsed = probes_from_cache(cached)
    if summary:
        csvwriter.writerow([
            "IP Address", "Censored Keyword", "Result Code",
            "TTL difference", "Censored T_TTL", "Control T_TTL",
            "Control Response Type", "Censorship Response Type",
            "Payloads Differ", "Control Payload", "Censored Payload",
            "On Path?",
            "Middlebox IP before", "AS/Country",
            "Middlebox IP", "AS/Country",
            "Middlebox IP after", "AS/Country",
            "RR IPs Censored", "RR IPs Uncensored",
            "Censored response IP features", "Control response IP features",
            "Middlebox differences", "All differences"])
        stdout = open(os.devnull, "w") # todo: cleaner logging
    if not os.path.exists(dirname):
        raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), dirname)
    probes = {}
    many_probes_per_sample = False
    for filename in glob(os.path.join(dirname, f"{prefix}*.pcap")):
        parts = os.path.basename(filename).split("_")
        if len(parts) == 3:
            ip, censored, tested = parts
            tested = tested.removesuffix(".pcap")
            if (ip, censored) not in probes:
                probes[(ip, censored)] = []
            probes[(ip, censored)].append(tested)
        else:
            many_probes_per_sample = True
            ip, censored, tested, n = parts
            n = int(n.removesuffix(".pcap"))
            if (ip, censored) not in probes:
                probes[(ip, censored)] = {}
            if tested not in probes[(ip, censored)]:
                probes[(ip, censored)][tested] = []
            probes[(ip, censored)][tested].append(n)
    random_probes = list(probes.items())
    random.shuffle(random_probes)
    for probe, tested in random_probes:
        if probe in parsed:
            continue
        stdout.write(str(probe))
        stdout.write("\n")
        ip, censored = probe
        uncensored = ""
        if not many_probes_per_sample:
            for word in tested:
                if word != censored:
                    uncensored = word
            result = main_compare_files(os.path.join(dirname, f"{ip}_{censored}_{censored}.pcap"),
                                  os.path.join(dirname, f"{ip}_{censored}_{uncensored}.pcap"), stdout)
        else:
            for word in tested.keys():
                if word != censored:
                    uncensored = word
            censored_probes = ProbeSet.from_pcaps([os.path.join(dirname, f"{ip}_{censored}_{censored}_{n}.pcap") for n in tested[censored]])
            uncensored_probes = ProbeSet.from_pcaps([os.path.join(dirname, f"{ip}_{censored}_{uncensored}_{n}.pcap") for n in tested[uncensored]])
            if censored_probes == None or uncensored_probes == None:
                result = ProbeAnalysis(ResponseCode.ERROR)
            else:
                result = main_compare(censored_probes.get_likeliest_path_by_ttl(),
                                      uncensored_probes.get_likeliest_path(), stdout)

        result_row = (ip, censored, result.response_code, result.ttl_diff(), result.censored_terminating_ttl, result.uncensored_terminating_ttl, result.control_response_type.value, result.censorship_type.value,
                result.payloads_differ,
                result.control_payload,
                result.censored_payload,
                result.on_path,
                result.middlebox_before, asn.lookup(ASNDB, result.middlebox_before),
                result.middlebox, asn.lookup(ASNDB, result.middlebox),
                result.middlebox_after, asn.lookup(ASNDB, result.middlebox_after),
                json.dumps(result.rrs_censored, default=_set_default),
                json.dumps(result.rrs_uncensored, default=_set_default),
                json.dumps(result.censored_terminating_features),
                json.dumps(result.control_terminating_features),
                json.dumps(result.middlebox_iph, default=_set_default),
                json.dumps(result.all_iph, default=_set_default))
        if not summary:
            input()
        else:
            csvwriter.writerow(result_row)
            old_stdout.flush()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", type=str, help="directory to read files from")
    parser.add_argument("--prefix", type=str, help=
                        "prefix of probes to display. Could be [server IP], or " + 
                        "[server IP]_[keyword] to specify particular measurements.")
    parser.add_argument("--file", type=str, help="filename of pcap to parse")
    parser.add_argument("--file2", type=str, help="filename of pcap to compare")
    parser.add_argument("--cached", type=str, help="filename of parsed pcap data")
    parser.add_argument("--summary", action="store_true", help="Print summary of all probes in dir.")
    parser.add_argument("-rv", "--routeviews_file", type=str)
    parser.add_argument("-an", "--asnames_file", type=str)
    parser.add_argument("-o", "--outfile", type=str)

    parser.set_defaults(dir=None, file=None, file2=None, outfile=None, prefix="", summary=False, cached=None)
    args = parser.parse_args()

    global ASNDB 
    ASNDB = asn.init(args.routeviews_file, args.asnames_file)

    if (args.dir and args.file) or not (args.dir or args.file):
        logging.error("Must provide at least one --dir or --file, but not both.")
        exit(1)

    stdout = sys.stdout
    if args.outfile:
        stdout = open(args.outfile, "w")
    if args.file2 and args.file:
        main_compare_files(args.file, args.file2, stdout)
        exit(0)
    elif args.file:
        main_file(args.file, stdout)
    elif args.dir:
        main_dir(args.dir, args.prefix, args.summary, stdout, cached=args.cached)

 
