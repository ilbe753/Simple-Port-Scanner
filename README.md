##Simple port scanner using Python Scapy

```
>_ sudo python3 simple-port-scanner.py --help

usage: [i] Simple Port Scanner [-h] -d DESTINATION [-p PORTS [PORTS ...]] -ps PORTSCANTYPE

optional arguments:
  -h, --help            show this help message and exit
  -d DESTINATION, --destination DESTINATION
                        Specify destination IP Address
  -p PORTS [PORTS ...], --ports PORTS [PORTS ...]
                        Specify destination ports (80 443 ...)
  -ps PORTSCANTYPE, --portscantype PORTSCANTYPE
                        Port Scan type, tcp_syn_scan|tcp_connect_scan|tcp_xmas_scan|tcp_fin_scan|tcp_null_scan
```
