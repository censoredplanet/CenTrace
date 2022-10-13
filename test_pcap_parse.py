import unittest
import os
import pcap_parse as pcap

TESTDATA_DIR = "./testdata/"

class TestPcapParse(unittest.TestCase):

    def _test_analysis(self, censored_filename, uncensored_filename, expected_result_code):
        censored = pcap.Probes.from_pcap(os.path.join(TESTDATA_DIR, censored_filename))
        uncensored = pcap.Probes.from_pcap(os.path.join(TESTDATA_DIR, uncensored_filename))
        result = pcap.analysis(censored, uncensored)
        self.assertEqual(result.response_code, expected_result_code)
        return result

    def test_parse_icmp_works(self):
        result = self._test_analysis(
                "188.65.24.82_www.nifty.org_www.nifty.org.pcap",
                "188.65.24.82_www.nifty.org_example.com.pcap",
                pcap.ResponseCode.CAN_IDENTIFY_SERVER)
        self.assertEqual(result.middlebox, "134.0.217.233")

    def test_parse_timeout(self):
        probes = pcap.Probes.from_pcap(os.path.join(TESTDATA_DIR, 
                    "188.65.24.82_www.nifty.org_www.nifty.org.pcap"))
        responses = [p.response_type() for p in probes.iter()]
        self.assertEqual(responses.count(pcap.ICMPResponse.TTL), 14)

    def test_parse_rst_injected_with_rst_control(self):
        result = self._test_analysis(
                "200.115.176.142_binance.com_binance.com.pcap",
                "200.115.176.142_binance.com_example.com.pcap",
                pcap.ResponseCode.CAN_IDENTIFY_SERVER)
        self.assertEqual(result.middlebox, "190.242.91.114")

    def test_parse_rst_injected(self):
        result = self._test_analysis(
                "188.65.24.82_www.nifty.org_www.nifty.org.pcap",
                "188.65.24.82_www.nifty.org_example.com.pcap",
                pcap.ResponseCode.CAN_IDENTIFY_SERVER)
        self.assertEqual(result.middlebox, "134.0.217.233")

    def test_parse_fin_injected(self):
        result = self._test_analysis(
                "103.93.208.20_bisexual.org_bisexual.org.pcap",
                "103.93.208.20_bisexual.org_example.com.pcap",
                pcap.ResponseCode.CAN_IDENTIFY_SERVER)
        self.assertEqual(result.middlebox, "149.14.125.90")

    def test_parse_endpoint_firewall(self):
        self._test_analysis(
            "91.199.201.114_www.bitcomet.com_www.bitcomet.com.pcap",
            "91.199.201.114_www.bitcomet.com_example.com.pcap",
            pcap.ResponseCode.ENDPOINT_FIREWALL)

    def test_parse_identify_middlebox_1_hop_before_endpoint(self):
        result = self._test_analysis(
            "195.46.232.198_minecraft.net_minecraft.net.pcap",
            "195.46.232.198_minecraft.net_example.com.pcap",
            pcap.ResponseCode.CAN_IDENTIFY_SERVER)
        self.assertEqual(result.middlebox, "194.154.209.226")

    def test_no_observed_censorship(self):
        self._test_analysis(
            "85.209.148.79_bridges.torproject.org_bridges.torproject.org.pcap",
            "85.209.148.79_bridges.torproject.org_example.com.pcap",
            pcap.ResponseCode.NO_OBSERVED_CENSORSHIP)

    def test_timeout_censorship(self):
        self._test_analysis(
            "185.236.34.4_store.steampowered.com_store.steampowered.com.pcap",
            "185.236.34.4_store.steampowered.com_example.com.pcap",
            pcap.ResponseCode.ENDPOINT_FIREWALL)

    def test_probe_terminated_early(self):
        self._test_analysis(
            "221.120.163.243_quora.com_quora.com.pcap",
            "221.120.163.243_quora.com_example.com.pcap",
            pcap.ResponseCode.TERMINATED_EARLY)

    def test_identify_onpath(self):
        result = self._test_analysis(
            "222.138.4.221_archive.org_archive.org.pcap",
            "222.138.4.221_archive.org_example.com.pcap",
            pcap.ResponseCode.CAN_IDENTIFY_SERVER)
        self.assertTrue(result.on_path)

    def test_parse_endpoint_firewall_different_routes(self):
        self._test_analysis(
            "62.28.164.41_www.bglad.com_www.bglad.com.pcap",
            "62.28.164.41_www.bglad.com_example.com.pcap",
            pcap.ResponseCode.NAT_FIREWALL)

    def test_parse_handshake_timeouts(self):
        probes = pcap.Probes.from_pcap(os.path.join(TESTDATA_DIR, "118.215.97.75_gawker.com_gawker.com.pcap"))
        responses = [p.response_type() for p in probes.iter()]
        self.assertEqual(responses.count(pcap.ErrorResponse.HANDSHAKE_TIMEOUT), 5)

    def test_parse_rr(self):
        probes = pcap.Probes.from_pcap(os.path.join(TESTDATA_DIR, "116.223.148.197_www.ft.com_www.ft.com.pcap"))
        self.assertEqual(len(probes.rrs.keys()), 9)

    def test_no_observed_censorship_tls(self):
        self._test_analysis(
            "95.167.150.101_sohu.com_sohu.com.pcap",
            "95.167.150.101_sohu.com_example.com.pcap",
            pcap.ResponseCode.NO_OBSERVED_CENSORSHIP)


    def test_multiple_file_format(self):
        self._test_analysis(
            "123.30.89.9_youtube.com_youtube.com_0.pcap",
            "123.30.89.9_youtube.com_example.com_0.pcap",
            pcap.ResponseCode.CAN_IDENTIFY_SERVER)

    def test_find_icmp_correctly(self):
        probes = pcap.Probes.from_pcap(os.path.join(TESTDATA_DIR, "116.202.120.183_bridges.torproject.org_example.com_0.pcap"))
        responses = [p.response_type() for p in probes.iter()]
        self.assertEqual(responses.count(pcap.ErrorResponse.TIMEOUT), 1)
        self.assertEqual(responses.count(pcap.ICMPResponse.TTL), 7)


    # In this case we can extract <IP1>:
    #   n+0: <IP0>   | <IP0>
    #   n+1: TIMEOUT | TIMEOUT
    #   n+2: TIMEOUT | <IP1>
    #   n+3: TIMEOUT | <IP2>

    def test_timeout_returns_potential_middleboxes(self):
        result = self._test_analysis(
            "94.20.71.165_www.pokerstars.com_www.pokerstars.com_0.pcap",
            "94.20.71.165_www.pokerstars.com_example.com_0.pcap",
            pcap.ResponseCode.CAN_IDENTIFY_SERVER)
        self.assertEqual(result.middlebox, "94.20.50.158")


if __name__ == "__main__":
    unittest.main()

