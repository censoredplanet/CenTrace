# CenTrace
[![Tests](https://github.com/censoredplanet/CenTrace/workflows/CenTrace/badge.svg)](https://github.com/censoredplanet/CenTrace/actions)

*Are you using `CenTrace`? If so, let us know! Shoot us an email at censoredplanet@umich.edu.*

`CenTrace` is a general-purpose application-layer censorship traceroute tool, that sends TTL-limited HTTP and TLS packets to detect the network locations of censorship devices. `CenTrace` can perform requests to different endpoints parallely using specified domains. It first tests to see whether there is any sign of interference for a particular measurement, by comparing responses with a control measurement. If there is an indication of blocking, it then performs multiple repetitions of two traceroutes to the endpoint - one with the test domain and the other with a control domain- to determine the network path to the endpoint, and the exact location of the blocking. `CenTrace` has the following features:
1.  It can detect censorship devices that inject packets (such as a TCP RST packet or a blockpage) as well as devices that drop packets (and induce a timeout).
2.  `CenTrace` can differentiate between in-path (processing packets at line rate) and on-path (receiving only a copy of the packets) devices.  
3.  `CenTrace` accounts for stateful blocking by including a customizable delay between successive traceroutes and measurements. 
4.  `CenTrace` follows the method used by [Tracebox](http://www.tracebox.org/) to compare the quoted packets in ICMP error response to detect middleboxes. 
5.  `CenTrace` uses the IP record-route option to add additional information about the location of middleboxes when the network path supports the option. 
6.  `CenTrace` repeats probes multiple times to account for network path variance and calculates the most likely location of the middlebox. 
7.  `CenTrace` can identify censorship devices that copy TTL values from the IP header of sent packets. 

`CenTrace` can record packet captures, and analyze them to produce a final outcome containing a response code (overall type of outcome), the type of censorship response, the terminating hops in the control and test `CenTrace` measurement, the payloads in the control and test `CenTrace` measurement and whether they differ, whether the device is on-path or in-path, and the IP, ASN, and Country of the censoring and surrounding hops. Each measurement is recorded in a different packet capture file (refer to `examples/pcaps/`). These `pcaps` can then be analyzed using the analysis component of `CenTrace`.

For more information, refer to [our paper](https://ramakrishnansr.org/publications). 

## Installation
- Install Python v3.9 or newer, see <https://www.python.org/downloads/release/python-390/>
- **Set your IPTABLES to drop outbound RST packets for the measurement, since `CenTrace` uses the [scapy](https://scapy.net/) library, which runs at user-level.**
- Install required dependencies using pip - `pip install -r requirements.txt`

## Configuration
The following flags can be provided for running measurements:
|         Flag           |          Default         |                       Function                         |                  Example                   |
| ---------------------- | ------------------------ | ------------------------------------------------------ | ------------------------------------------ |
| censored_keyword       | Required if no filename  | Domain to include in test measurements                 | `google.com`                               |
| censored_keyword       | `example.com`            | Domain to include in control measurements              | `example.com`                              |
| server_ip              | Required if no filename  | IP of endpoint to send measurements to                 | `1.1.1.1`                                  |
| verbose                | False                    | Print debug output                                     |                                            |
| https                  | False                    | Send HTTP (false) or TLS (true) measurements           |                                            |
| iprr                   | False                    | Try including IP record route option if true           |                                            |
| tracebox               | False                    | Run a Tracebox measurement additionally (requires [Tracebox](http://www.tracebox.org/) to be installed) |                                            |
| interface              | Picked by default        | Interface to send measurements from                    |                                            |
| filename               | Required if no server_ip | A csv file with `endpoint, domain` pairs to measure    | `examples/input.csv`                       |
| outfile                | stdout                   | A csv file to write final output in (use pcaps for full output)           | `examples/output.csv`                                           |
| verbosefile            | stderr                   | File in which to write log output in                   |                                            |
| max_threads            | 1                        | No. of parallel measurements to run                    |                                            |
| rate                   | 3                        | Delay in seconds between each TTL probe                |                                            |
| separation             | 120                      | Delay in seconds between measurements to same endpoint |                                            |
| save_pcaps             | False                    | Save packet captures if true                           |                                            |
| pcap_dir               | `pcaps/`                 | Folder to save pcap output in                          | `examples/pcaps/`                          |
| consistent_runs        | 5                        | Number of consistent path runs to see before terminating   |                                            |
| max_iterations         | 11                       | Maximum number of repetitions for each measurement     |                                            |
| routeviews_file        | Required                 | Data from Routeviews to get ASN information            |                                            |
| asnames_file           | Required                 | AS Number to Name mapping from [`pyasn`](https://github.com/hadiasghari/pyasn/blob/master/pyasn-utils/pyasn_util_asnames.py)                 |                                            |

The following flags can be provided for analyzing pcaps:

|         Flag           |          Default         |                       Function                         |           Example             |
| ---------------------- | ------------------------ | ------------------------------------------------------ | ----------------------------- |
| dir                    | Required                 | Directory to read pcap files from                      | `examples/pcaps`              |
| prefix                 | ""                       | Prefix of probes to display. Can be `server_ip_`        | `195.64.201.42_psiphon.ca`   |
| routeviews-file        | Required                 | Data from Routeviews to get ASN information            |                               |
| asnames_file           | Required                 | AS Number to Name mapping from [`pyasn`](https://github.com/hadiasghari/pyasn/blob/master/pyasn-utils/pyasn_util_asnames.py)                 |                                            |
| file                  | ""                       | Specific filename to parse                             |                               |
| file2                 | ""                       | Filename to compare with previous argument             |                               |
| summary               | False                    | Print summary of all probes in directory               |                               |
| outfile                | stdout                  | A csv file to write final output in                   | `examples/analyzed_output.csv`|

 
## Usage
The `CenTrace` tool provides two functions:
1. Run traceroute measurements across a list of endpoints: 
```
sudo python3 traceroute.py --filename examples/input.csv -o examples/output.csv -v -l examples/log.txt --iprr --comparequoted -r 5 -R 120 -p -pd examples/pcaps -m 2 -i enp1s0f1 -rv routeviews_file -an asnames_file
```
2. Analyze pcaps:
 ```
python3.9 pcap_parse.py --dir examples/pcaps/ -rv routeviews_file -an asnames_file --summary -o examples/analyzed_output.csv 
```

## Disclaimer
Russing `CenTrace` from your machine may place you at risk if you use it within a highly censoring regime. `CenTrace` takes actions that try to trigger censoring middleboxes multiple times, and try to interfere with the functioning of the middlebox. Therefore, please exercice caution while using the tool, and understand the risks of running `CenTrace` before using it on your machine. Please refer to [our paper](https://ramakrishnansr.org/publications) for more information. 

## Data
The fuzzing measurement data from the study in [our paper](https://ramakrishnansr.org/publications) can be found [here](https://drive.google.com/drive/folders/1pZWOJWDnX_0_BmXrfvC_9WOrurcPZ4lF?usp=sharing). 

## Citation
If you use the `CenTrace` tool or data, please cite the following publication:
```
@inproceedings{sundararaman2022network,<br>
title = {Network Measurement Methods for Locating and Examining Censorship Devices},<br>
author = {Sundara Raman, Ram and Wang, Mona and Dalek, Jakub and Mayer, Jonathan and Ensafi, Roya},<br>
booktitle={In ACM International Conference on emerging Networking EXperiments and Technologies (CoNEXT)},<br>
year={2022}
```

## Contributing
Censorship measurements are constanlt improving to adapting to the changing censorship landscape, and we need the help of the community to improve `CenTrace` and keep it updated! We welcome any and all contributions. Please feel free to open an Issue, Pull Request, or send us an email.

## Licensing
This repository is released under the GNU General Public License (see [`LICENSE`](LICENSE)).

## Contact
Email addresses: `censoredplanet@umich.edu`, `ramaks@umich.edu`, `monaw@princeton.edu`, `jakub@citizenlab.ca`, `jonathan.mayer@princeton.edu`, and `ensafi@umich.edu`

## Contributors

[Ram Sundara Raman](https://github.com/ramakrishnansr)

[Mona Wang](https://github.com/m0namon)


