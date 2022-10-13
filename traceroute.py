""" Usage: traceroute.py -s <vantage point IP> -c <censored keyword> -u <uncensored keyword> [--https] [--outfile <filename>]

Launches increasing-TTL probes with both censored and uncensored keywords.
If https is set, launches HTTPS probes pre-recorded TLS ClientHello.
Otherwise launches HTTP probe with keyword as HTTP Host header.

To read from file, can run:
  probe.py -f <filepath> -u <uncensored keyword [--https] [--outfile <filename>]

File should be a CSV with the server IP in the first column and the censored keyword in the second.
For instance:
  1.2.3.4, facebook.com
  5.6.7.8, nytimes.com

If outfile is not provided, results are written to stdout.
"""

from abc import ABC, abstractmethod
import csv
import datetime
import json
import argparse
import json
import os
from re import VERBOSE
import sys
import logging
import subprocess
import traceback
import concurrent.futures
import sniffer
import time

import tcp
import asn


from scapy.all import *
load_layer("http")
load_layer("tls")

DEFAULT_UNCENSORED_KEYWORD = "example.com"

MAX_JOBS_IN_QUEUE = 128

ICMP_RESPONSES = ("ICMP_TTL", "ICMP_OTHER")
TCP_RESPONSES = ("RST", "FIN", "ACK")
APP_RESPONSES = ("TLS", "HTTP")
OTHER_RESPONSES = ("HANDSHAKE_TIMEOUT", "TIMEOUT")

# This determines the precedence of response types. That is, if a packet contains
# (ICMP, ACK, TLS) layers, we consider that an ICMP response. If a packet contains only
# (ACK, TLS) layers, we consider that a valid TLS response.
# Make this RESPONSE_PRECEDENCE = () to view all layers
RESPONSE_PRECEDENCE = (*list(ICMP_RESPONSES), *list(APP_RESPONSES), *list(TCP_RESPONSES))

def set_default(obj):
    if isinstance(obj, set):
        return list(obj)
    raise TypeError


def _match_path_prefix(full_path, prefix_path):
    for i, _as in enumerate(full_path):
        if i >= len(prefix_path) - 1:
            break
        if prefix_path[i] != _as:
            return False
    return True

class TTLProbe(ABC):
    def __init__(self, server_ip, iprr, verbose, comparequoted, rate, save_pcaps, pcap_dir, pcap_file, dport=80, max_ttl=64, timeout=3, iface=None):

        self.max_ttl = max_ttl
        self._hostname = None
        self._probedata = None
        self._timeout = timeout
        self._interface = iface or 'any'
        self.server_ip = server_ip
        self.dport = dport
        self.iprr = iprr
        self.verbose = verbose
        self.comparequoted = comparequoted
        self.rate = rate
        self.save_pcaps = save_pcaps
        self.pcap_dir = pcap_dir
        self.pcap_file = pcap_file
        self.tcp_conn = None

    def get_probe_data(self, hostname):
      """ Retrieves or constructs probe TCP payload for a particular keyword/hostname. """
      if self._probedata is None or self._hostname != hostname:
        self._probedata = self._build_probe_data(hostname)
        self._hostname = hostname
      return self._probedata

    @abstractmethod
    def _build_probe_data(self, hostname):
      """ Constructs TCP payload using a particular keyword/hostname for this probe. 

      We don't know what kind of probe we are, so we can't do it in the base class. """
      raise NotImplementedError

    def full_probe_response(self, keyword):
        port = random.randint(49152, 65535)
        data = self.get_probe_data(keyword)
        single_probe_responses, _ = self.single_probe(data, self.max_ttl, port, "")
        return single_probe_responses

    #Test handshake to see whether the path supports IP options
    def test_iprr_viable(self, server_ip, verbose_output):
        iprr_conn = tcp.TCPSession(server_ip, self.dport, interface=self._interface)
        iprr_conn.set_iprr()

        if not iprr_conn.handshake():
            self.iprr = False
            return self.iprr, verbose_output
        if self.verbose:
            verbose_output += "RR option enabled"
        iprr_conn.close()
        return self.iprr, verbose_output

    def get_bpf(self, min_port, max_port):
        dummysession = tcp.TCPSession(self.server_ip, self.dport, interface=self._interface)
        if self.iprr:
            dummysession.set_iprr()
        sport_offset  = 8 + dummysession.iph_length() # ICMP header length + IP header length
        return f"host {self.server_ip} or (icmp[0] = 11 and icmp[{sport_offset}:2] >= {min_port} and icmp[{sport_offset}:2] < {max_port})"

    def pcap_filepath(self, hostname, run):
        return os.path.join(self.pcap_dir, f"{self.server_ip}_{self.pcap_file}_{hostname}_{run}.pcap")

    def pcap_exists(self, hostname):
        return os.path.exists(self.pcap_filepath(hostname, 0))


    def run_until_prefix(self, hostname, path_to_prefix, verbose_output, max_iter=9):
        run_count = 0
        results = []
        while True:
            result, v_out = self.run(hostname, verbose_output, run_count)
            results.append(result)
            verbose_output += v_out
            as_list = _results_to_as_list(result)
            if _match_path_prefix(path_to_prefix, as_list):
                return results[-1], as_list, verbose_output
            run_count += 1
            if run_count >= max_iter:
                # Return arbiitrary result if past max_iter
                return results[-1], None, verbose_output

    def run_until_consistent(self, hostname, verbose_output, consistent_runs=3, max_iter=9):
        count = {}
        results = []
        run_count = 0
        while True:
            result, v_out = self.run(hostname, verbose_output, run_count)
            results.append(result)
            verbose_output += v_out
            as_list = _results_to_as_list(result)
            if as_list not in count:
                count[as_list] = 0
            count[as_list] += 1
            for v in count.values():
                if v >= consistent_runs:
                    # Final result is guaranteed to be consistent
                    return results[-1], as_list, verbose_output
            run_count += 1
            if run_count >= max_iter:
                # Return leading max result if past max_iter
                return results[-1], max(count, key=count.get), verbose_output

    def run(self, hostname, verbose_output, n):
        """ Runs TTL probe with keyword `hostname`. """
        self.startport = random.randint(49152, 65535 - self.max_ttl - 1)
        data = self.get_probe_data(hostname)
        pcap_file = self.pcap_filepath(hostname, n)
        if self.save_pcaps:
            pcap_sniffer = sniffer.TCPDumpPacketSniffer(self.get_bpf(self.startport, self.startport+self.max_ttl), iface=self._interface)
            pcap_sniffer.start()
        try:
            responses = []
            for i in range(0, self.max_ttl):
                port = self.startport + i
                single_probe_responses, verbose_output = self.single_probe(data, i, port, verbose_output)
                responses.append(single_probe_responses)
                icmp_or_timeout = False
                for _, _, response_types, _, _ in single_probe_responses:
                    if "ICMP_TTL" in response_types or "TIMEOUT" in response_types:
                        icmp_or_timeout = True
                if not icmp_or_timeout:
                    break
                time.sleep(self.rate) #Sleep three seconds before trying to ping again
        finally:
            if self.save_pcaps:
                pcap_sniffer.stop_and_write_async(pcap_file)
        return responses, verbose_output

    #TODO: This function currently only compares known header values and does not look for additional headers. 
    #TODO: (IMP) Check for additional headers added to the packet similar to tracebox. 
    def compare_quoted_packets(self,req,res):
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

    def _get_layers(self, req, packet, verbose_output):
        layers = set()
        quoted_differences = set()
        payload = ""
        if packet.haslayer("ICMP"):
            if packet[ICMP].type == 11:
                layers.add("ICMP_TTL")
            else:
                layers.add("ICMP_OTHER")
            if self.comparequoted:
                quoted_differences = self.compare_quoted_packets(req, packet)
        if packet.haslayer("TCP"):
            if 'R' in packet[TCP].flags:
                layers.add("RST")
            elif 'F' in packet[TCP].flags:
                layers.add("FIN")
            elif 'A' in packet[TCP].flags:
                layers.add("ACK")
            try:
                payload = packet[TCP].payload.load
                payload = payload.decode("utf-8") + ";"
            except:
                payload = ""
        return layers, list(quoted_differences), payload, verbose_output

    def process_response_packet(self, req, packet, verbose_output):
        layers, quoted_differences, payload, verbose_output = self._get_layers(req, packet, verbose_output)
        for response in RESPONSE_PRECEDENCE:
            if response in layers:
                return set([response]), quoted_differences, payload, verbose_output
        # If no layer in the precedence list, just return all the layers
        return layers, quoted_differences, payload, verbose_output

    def single_probe(self, data, ttl, port, verbose_output):
        """ Run a single TCP probe """
        self.tcp_conn = tcp.TCPSession(self.server_ip, self.dport, sport=port, timeout=self._timeout, interface=self._interface)
        if not self.tcp_conn.handshake():
            return [(ttl, None, "HANDSHAKE_TIMEOUT", None, "")], verbose_output

        if self.iprr:
            self.tcp_conn.set_iprr()
        
        req = None
        responses = []
        try:
            req, responses = self.tcp_conn.sendrecv(data, ttl, retries=3)
        except Exception as e:
            sys.stderr.write("Packet sending error: " + str(e) + "\n") #Debug
            return [(ttl, None, "ERROR SENDING PACKET", "", "")], verbose_output

        results = []
        for packet in responses:
            result_type, quoted_differences, payload, verbose_output = self.process_response_packet(req, packet, verbose_output)
            results.append((ttl, packet[IP].src, result_type, quoted_differences, payload))

        if len(results) == 0:
            results.append((ttl, None, "TIMEOUT", None, ""))

        if not self.tcp_conn.close():
            verbose_output += "Warning: Failed to close connection for probe.\n"

        return results, verbose_output


class HTTPProbe(TTLProbe):
    def _build_probe_data(self, hostname):
        with open("http.template", "rb") as file:
            http_template = file.read()
        return http_template.replace(b"HOSTNAME", bytes(hostname, "utf-8"))

    def _get_layers(self, req, packet, verbose_output):
        # TODO:: differentiate different types of HTTP responses
        layers, quoted_differences, payload, verbose_output = super()._get_layers(req, packet,verbose_output)
        if packet.haslayer(HTTPResponse):
             layers.add("HTTP")
             payload += packet[HTTPResponse].show(dump=True) + ";"
        return layers, quoted_differences, payload, verbose_output


class HTTPSProbe(TTLProbe):
    def __init__(self, server_ip, iprr, verbose, comparequoted, rate, save_pcaps, pcap_dir, pcap_file, dport=443, max_ttl=64, timeout=3, iface=None):
        super().__init__(server_ip, iprr, verbose, comparequoted, rate, save_pcaps, pcap_dir, pcap_file, dport, max_ttl, timeout, iface=iface)

    def _build_probe_data(self, hostname):
        sni = scapy.layers.tls.extensions.ServerName(servername=hostname)
        extensions = scapy.layers.tls.extensions.TLS_Ext_ServerName(type=0, servernames=sni)
        cipher_suites = [0x1301,0x1302,0x1303,0xc02b,0xc02c,0xc02f,0xc030,0xcca9,0xcca8,0xc013,0xc014,0x009c,0x009d,0x002f,0x0035,0x000a,0x009f]
        client_random = os.urandom(32) 
        client_hello = scapy.layers.tls.handshake.TLSClientHello(version=0x0303,random_bytes=client_random,sidlen=0x00,ciphers=cipher_suites,complen=0x01,comp=0x00,ext=extensions)
        message = scapy.layers.tls.record.TLS(type=0x16,version=0x0301,msg=client_hello)
        return message
        

    def _get_layers(self, req, packet, verbose_output):
        # TODO:: differentiate different types of TLS responses
        layers, quoted_differences, payload, verbose_output = super()._get_layers(req, packet, verbose_output)
        if packet.haslayer("TLS"):
            layers.add("TLS")
            payload += packet["TLS"].show(dump=True) + ";"
        return layers, quoted_differences, payload, verbose_output

def _probe_result_to_as(result):
  hop, src_ip, _, _, _ = result
  if src_ip is not None:
    ip_asn = asn.lookup(ASNDB, src_ip)
    if ip_asn == None or str(ip_asn[0]) == "None":
      return None
    else:
      return ip_asn[0]
  return None

def _results_to_as_list(results):
  ases = []
  for responses in results:
    probe_result = responses[0]
    ases.append(_probe_result_to_as(probe_result))
  return tuple(ases)

def make_probe(server_ip, https=False, iprr=False, verbose=False, comparequoted=False, rate=3, save_pcaps=False, pcap_dir="pcaps", pcap_file = "", iface=None):
    """ probe factory """
    if https:
        return HTTPSProbe(server_ip, iprr, verbose, comparequoted, rate, save_pcaps, pcap_dir, pcap_file, iface=iface)
    return HTTPProbe(server_ip, iprr, verbose, comparequoted, rate, save_pcaps, pcap_dir, pcap_file, iface=iface)


def responses_differ(censored_responses, control_responses):
    if len(censored_responses) != len(control_responses):
        return True
    # Do a best effort check to see if the responses differ or not.
    #   Note: The response format is (ttl, src_ip, result_type, quoted_differences, payload)
    censored_response = [r for r in censored_responses if list(r[2])[0] in APP_RESPONSES]
    control_response = [r for r in censored_responses if list(r[2])[0] in APP_RESPONSES]
    if len(censored_response) != len(control_response):
        return True
    if len(censored_response) > 0 and len(control_response) > 0:
      return censored_response[0][4] != control_response[0][4]
    return True # Default to performing probes if we are unsure

def run_and_compare(server_ip, censored_keyword, uncensored_keyword="example.com", https=False, iprr=False, verbose=False, comparequoted=False, verbose_output="", rate=3, save_pcaps=False, pcap_dir="pcaps", iface=None, consistent_runs=5, max_iterations=11):
    """ runs ttl probes for both censored & uncensored keywords """
    # TODO:: due to load-balancing, the IPs on these two paths can occasionally differ,
    # though they are often in the same subnet
    probe = make_probe(server_ip, https, iprr, verbose, comparequoted, rate, save_pcaps, pcap_dir, censored_keyword, iface)

    # Test whether responses differ.
    censored_response = probe.full_probe_response(censored_keyword)
    control_response = probe.full_probe_response(uncensored_keyword)
    if not responses_differ(censored_response, control_response):
        return None, None, None, "Application responses do not differ; no censorship observed"

    # Test whether viable to send iprr option. 
    if iprr:
        iprr, verbose_output = probe.test_iprr_viable(server_ip, verbose_output)

    if probe.pcap_exists(uncensored_keyword) and probe.pcap_exists(censored_keyword):
        return None, None, None, "Probe already run; PCAP files already exist\n"
    #run uncensored first so that stateful blocking is prevented
    uncensored, _, verbose_output = probe.run_until_consistent(uncensored_keyword, verbose_output, consistent_runs, max_iterations)
    censored, _, verbose_output = probe.run_until_consistent(censored_keyword, verbose_output, consistent_runs, max_iterations)
    
    return censored, uncensored, iprr, verbose_output

def is_ip_alive(server_ip, dport, interface=None,retries=3):
    alive = False
    for _ in range(retries):
        tcp_conn = tcp.TCPSession(server_ip, dport, interface=interface)
        if not tcp_conn.handshake():
            continue
        if tcp_conn.close():
            alive = True
            break
        time.sleep(3)
    return alive

def cli(server_ip, censored_keyword, uncensored_keyword, https=False, iprr = False, verbose = False, comparequoted=False, tracebox=False, rate=3, save_pcaps=False, pcap_dir="pcaps", iface=None, consistent_runs=5, max_iterations=11):
    logging.info(server_ip)
    #Intialize empty string for verbose output
    verbose_output = ""
    if verbose:
        verbose_output = "\n\n****************************************\n"
        verbose_output += server_ip + "," + censored_keyword +  "\n"
    
    if https:
        alive = is_ip_alive(server_ip, 443, iface)
    else:
        alive = is_ip_alive(server_ip, 80, iface)
    
    if not alive:
        verbose_output += "Server IP not responding to TCP handshake"
        return None, verbose_output

    censored, uncensored, iprr, verbose_output = run_and_compare(server_ip, censored_keyword, uncensored_keyword, https, iprr, verbose, comparequoted, verbose_output, rate, save_pcaps, pcap_dir, iface, consistent_runs, max_iterations)
    if censored is None: # Skip scan since pcaps already exist
        return "", verbose_output
    if tracebox:
        tracebox_output = subprocess.run(["sudo","tracebox","-n", "-j", server_ip], capture_output=True)
    
    output = server_ip + "|" + censored_keyword + "|" + str(iprr) + "|" + json.dumps(censored, default=set_default) + "|" + json.dumps(uncensored, default=set_default)
    if tracebox:
        output += "|" + json.dumps(str(tracebox_output.stdout))
    output += "\n"
    return output, verbose_output


def cli_file(filename, uncensored, https=False, iprr = False, verbose = False, comparequoted = False, tracebox = False, rate=3, separation=120, max_threads=1, save_pcaps=False, pcap_dir="pcaps", iface=None, consistent_runs=5, max_iterations=11, outfile=sys.stdout, verbose_file=sys.stderr):
    with open(filename) as csvfile:
        filereader = csv.reader(csvfile)

        #Before measurements, store in memory the set of measurements to be conducted in each round,  
        ases = {}
        schedule = {}
        for row in filereader:
            #Inputs now need to provide the ASN.
            server_ip, censored_keyword, asn = row
            #Use a loop variable to assign the schedule
            loopVar = 0
            while loopVar > -1:
                if loopVar not in ases or asn not in ases[loopVar]:
                    ases[loopVar] = {}
                    ases[loopVar][asn] = set()
                if ((loopVar not in schedule or server_ip not in schedule[loopVar]) and len(ases[loopVar][asn]) < 5):
                    if loopVar not in schedule:
                        schedule[loopVar] = {}
                    schedule[loopVar][server_ip] = censored_keyword
                    ases[loopVar][asn].add(server_ip)
                    break
                else:
                    loopVar += 1
        for measurement_count, measurement_dict in schedule.items():
            sys.stderr.write("Measurement Round: " + str(measurement_count) + "\r")
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor: 
                #Batch internally to avoid using up too much RAM
                jobs = {}
                while len(measurement_dict) > 0:
                    for server_ip, censored_keyword in measurement_dict.items():
                        future_to_cli = executor.submit(cli, server_ip, censored_keyword, uncensored, https, iprr, verbose, comparequoted, tracebox, rate, save_pcaps, pcap_dir, iface, consistent_runs, max_iterations)
                        jobs[future_to_cli] = server_ip
                        #Break if too many jobs are assigned. More jobs can be assigned to all workers when current set is done. 
                        if len(jobs) > MAX_JOBS_IN_QUEUE:
                            break
                    
                    for future in concurrent.futures.as_completed(jobs):
                        try:
                            output, verbose_output = future.result()
                        except Exception as exc:
                            print('%r generated an exception: %s\n' % (row, exc))
                            print(traceback.format_exc())
                        else:
                            if verbose == True:
                                verbose_file.write(verbose_output)
                            if output:
                                outfile.write(output)  
                        server_ip = jobs[future]
                        #Delete data from dict that is already done and free up memory
                        del measurement_dict[server_ip]
                        del jobs[future]
                    
            #Sleep for 2 minutes to avoid effects of stateful blocking as emperically determined by Cenosred Planet
            time.sleep(separation)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--censored_keyword", type=str)
    parser.add_argument("-u", "--uncensored_keyword", type=str)
    parser.add_argument("-s", "--server_ip", type=str)
    parser.add_argument("--https", action="store_true")
    #Flag for verbose output which prints packets
    parser.add_argument("-v","--verbose", action="store_true")
    #Flag for setting whether to send record route in IP header
    parser.add_argument("--iprr", action="store_true")
    #Flag for comparing quoted ICMP replies with original packet similar to Tracebox
    parser.add_argument("-q", "--comparequoted", action="store_true")
    #Run original tracebox command as an additional measurement
    parser.add_argument("-t", "--tracebox", action="store_true")
    parser.add_argument("-i", "--interface", type=str)
    parser.add_argument("-f", "--filename", type=str)
    parser.add_argument("-o", "--outfile", type=str)
    parser.add_argument("-l","--verbosefile", type=str)
    parser.add_argument("-m","--max_threads", type=int)
    #Rate at which the incrementing TTL probes should be sent 
    parser.add_argument("-r","--rate",type=int)
    #Time between measurements to the same vantage points
    parser.add_argument("-R","--separation",type=int)
    # Whether to store pcaps of the probes.
    parser.add_argument("-p", "--save_pcaps", action="store_true")
    parser.add_argument("-pd", "--pcap_dir", type=str)
    parser.add_argument("-cr", "--consistent_runs", type=int)
    parser.add_argument("-mi", "--max_iterations", type=int)
    parser.add_argument("-rv", "--routeviews_file", type=str)
    parser.add_argument("-an", "--asnames_file", type=str)
    parser.set_defaults(https=False, verbose=False, iprr=False, comparequoted=False, tracebox=False, filename="", server_ip="", outfile="",verbosefile="",max_threads=1, rate=3, save_pcaps=False, pcap_dir="pcaps", interface=None, separation=120, uncensored_keyword=DEFAULT_UNCENSORED_KEYWORD, consistent_runs=5,max_iterations=11,routeviews_file="",asnames_file="")

    args = parser.parse_args()

    global ASNDB 
    ASNDB = asn.init(args.routeviews_file, args.asnames_file)

    stdout = sys.stdout
    if args.outfile:
        stdout = open(args.outfile, "w")
    stderr = sys.stderr
    if args.verbosefile:
        stderr = open(args.verbosefile,"w")

    timestr = datetime.now().strftime("%Y_%m_%d")
    pcap_dir = "pcaps"
    if args.pcap_dir:
        pcap_dir = args.pcap_dir
    if not os.path.exists(pcap_dir):
        os.makedirs(pcap_dir)

    if args.tracebox:
        try:
            tracebox_run = subprocess.run(["sudo","tracebox","-V"], capture_output=True)
            if not tracebox_run.stderr.startswith(b'v'):
                sys.stderr.write("Tracebox error. Ensure `sudo tracebox -V` shows the version number\n")
                sys.stderr.write("Continuing without tracebox\n")
                args.tracebox = False
        except Exception as e:
                sys.stderr.write("Tracebox error (May not be installed correctly, please install from https://github.com/tracebox/tracebox)\n")
                sys.stderr.write("Error: " + str(e))
                sys.stderr.write("Continuing without tracebox\n")
                args.tracebox = False
    try:
      if args.server_ip:
        if not args.censored_keyword:
          logging.error("Need to provide --censored_keyword to test probe with.")
          sys.exit(1)
        output, verbose_output = cli(args.server_ip, args.censored_keyword, args.uncensored_keyword, args.https, args.iprr, args.verbose, args.comparequoted, args.tracebox, args.rate, args.save_pcaps, pcap_dir, args.interface, args.consistent_runs, args.max_iterations)
        if args.verbose:
            stderr.write(verbose_output)
            stderr.flush()

        stdout.write(output)
        stdout.flush()
      elif args.filename:
        cli_file(args.filename, args.uncensored_keyword, args.https, args.iprr, args.verbose, args.comparequoted, args.tracebox, args.rate, args.separation, args.max_threads, args.save_pcaps, pcap_dir, args.interface, args.consistent_runs, args.max_iterations, stdout, stderr)
      else:
        logging.error("Need to provide either --server_ip or --filename.")
        sys.exit(1)
    finally:
      if args.outfile:
        stdout.close()
      if args.verbosefile:
        stderr.close()
      time.sleep(120) # sleep 2 x sniffer delay time
    sys.exit(0)
