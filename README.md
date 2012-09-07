
# ipforge.py

> Copyright (c) 2012 Martin Carpenter, mcarpenter@free.fr

## Introduction

ipforge uses python's scapy module to forge single IP packets (TCP or
UDP) with given source and destination address and insert them into the
network. Sample uses might be port knocking, or poking at firewalls, IDS
or other network devices. Requires root privileges on the sending host.

## Command line usage

    ipforge.py -h
    ipforge.py [-d data] [-f flags] [-i iface] [-p {tcp|udp}] [-v{0..3}] src[:sport] dst[:dport]

    -d data
    String of data to include in the packet.

    -f flags
    TCP flags to set on the packet (not valid to UDP).

    -i iface
    The interface by which to insert the packet onto the network, eg eth0.

    -p {tcp|udp}
    Select the protocol to use.

    -v{0..3}
    The scapy verbosity level. Default is 0.

    src[:sport]
    The source IP address and (optional) source port. If the source port
    is not specified then one is chosen at random from 0..65535.

    dst[:dport]
    The destination IP address and (optional) destination port. If
    the destination port is not specified then one is chosen at random
    from 0..65535.

## Python module usage

    #!/usr/bin/env python
    from ipforge import ipforge
    ipforge(src='192.168.1.66', dst='192.168.1.51', dport=666, flags='S')

