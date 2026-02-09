# demo-nw-analyzer

This is a demo to capture traffic of a remote machine that only uses tcpdump.

There are some cases that you cannot install tshark/wireshark in the remote machine and only you can use tcpdump to monitorize the packages of a interface. This script do that without sending or installing anything in the remote machine, only tcpdump.

### Remote Machine
* `tcpdump` captures raw traffic on a network interface
* Outputs a binary PCAP stream
* Sends data through SSH

### Local side (Python application)
* SSH (Paramiko) transports the PCAP stream
* Forked stream (save data and analyze data)

#### Persistence
* Writes a full `.pcap`

#### Analysis
* Executa lua dissectors
* Outputs **PDML(XML)**

### Business logic
* Searches patterns
* Detects conditions
* Operates in real time without blocking capture

```
┌──────────────────────────┐
│   Remote Machine         │
│                          │
│  ┌────────────────────┐  │
│  │ tcpdump            │  │
│  │ (interface eno1)   │  │
│  │                    │  │
│  │ - captures traffic │  │
│  │ - outputs PCAP     │  │
│  │   binary stream    │  │
│  └────────┬───────────┘  │
│           │ stdout       │
└───────────┼──────────────|
            │  (PCAP stream over SSH)
            ▼
┌──────────────────────────────────────────┐│
│   Local Machine / Python Application     ││
│                                          ││
│  ┌────────────────────────────────────┐  ││
│  │ Paramiko SSH Channel               │  ││
│  │                                    │  ││
│  │ - receives PCAP byte stream        │  ││
│  └───────────────┬────────────────────┘  ││
│                  │                       ││
│          PCAP stream duplication         ││
│                  │                       ││
│      ┌───────────┴───────────┐           ││
│      ▼                       ▼           ││
│ ┌───────────────┐     ┌───────────────┐  ││
│ │ tshark #1     │     │ tshark #2     │  ││
│ │ PCAP Writer   │     │ Analyzer      │  ││
│ │               │     │               │  ││
│ │ - reads PCAP  │     │ - reads PCAP  │  ││
│ │ - writes file │     │ - runs Lua    │  ││
│ │   capture.pcap│     │ - outputs PDML│  ││
│ └───────┬───────┘     └───────┬───────┘  ││
│         │                     │          ││
│         │                     │ stdout   ││
│         │                     ▼          ││
│         │          ┌──────────────────┐  ││
│         │          │ PDML XML Parser  │  ││
│         │          │                  │  ││
│         │          │ - <packet> → XML │  ││
│         │          │ - ElementTree    │  ││
│         │          └─────────┬────────┘  ││
│         │                    │           ││
│         │          ┌─────────▼────────┐  ││
│         │          │ Shared Packet    │  ││
│         │          │ Buffer           │  ││
│         │          │ (thread-safe)    │  ││
│         │          └─────────┬────────┘  ││
│         │                    │           ││
│         │          ┌─────────▼───────-┐  ││
│         │          │ Business Logic   │  ││
│         │          │                  │  ││
│         │          │ - pattern match  │  ││
│         │          │ - timeouts       │  ││
│         │          │ - real-time eval │  ││
│         │          └──────────────────┘  ││
│                                          ││
│  ┌────────────────────────────────────┐  ││
│  │ Lifecycle Management               │  ││
│  │                                    │  ││
│  │ - start_sniff()                    │  ││
│  │ - stop_sniff()                     │  ││
│  │ - resource cleanup                 │  ││
│  └────────────────────────────────────┘  ││
└──────────────────────────────────────────┘┘

```
### Usage

```
usage: Networker [-h] [-d DIRECTION] [-f FILTER] [-i INTERFACE] [-u USER] [-p PASSWORD] [-x LUA_SCRIPT]

This program captures and search patterns in the packages

options:
  -h, --help            show this help message and exit
  -d, --direction DIRECTION
                        IP or domain name server of the remote machine
  -f, --filter FILTER   wireshark filter
  -i, --interface INTERFACE
                        Select an interace
  -u, --user USER       Remote user
  -p, --password PASSWORD
                        Remote user
  -x, --lua_script LUA_SCRIPT
                        LUA Script path
```
