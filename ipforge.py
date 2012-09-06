#!/usr/bin/env python
#
# ipforge.py
#
# Forge and send TCP/IP or UDP/IP packets. Requires superuser privilege on
# the sending host.
#
# Copyright (c) 2012 Martin Carpenter, mcarpenter@free.fr
#

import getopt
import sys
import re
from random import randint
# Disable warnings (eg because IPv6 disabled)
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import IP,TCP,UDP,conf,send

def error(msg, exit=None):
    """Write error message to stderr prefixed by program name and optionally exit."""
    print >>sys.stderr, "ipforge.py: %s" % msg
    if exit is not None:
        sys.exit(exit)

def usage(msg, exit=None):
    "Print message and usage on stderr and optionally exit."""
    if msg != '': error(msg)
    print >>sys.stderr, "ipforge.py -h | [-d data] [-i iface] [-f flags] [-p {tcp|udp}] [-v 0..3] src[:src_port] dst[:dst_port]"
    if exit is not None:
        sys.exit(exit)

def parse_address(address):
    """Parses the IP address/port argument and returns a tuple with port
    coerced to an int."""
    ip = None
    port = None
    match = re.match("^(\d+\.\d+\.\d+\.\d+)(:(\d+))?$", address)
    if match:
        ip = match.group(1)
        port_str = match.group(3)
        if port_str:
            try:
                port = int(port_str)
            except ValueError:
                error("invalid port %s" % port_str)
    else:
        error("invalid address %s" % address, 2)
    return((ip, port))

def random_port():
    """Generate a random port number in the range 0..65535 inclusive."""
    return randint(0, 65535)

def ipforge(protocol=None, src=None, sport=None, flags=None, dst=None, dport=None, data=None, iface=None, verbosity=0):
    """Forge and send an IP packet."""
    if sport is None: sport = random_port()
    if dport is None: dport = random_port()
    if protocol is None: protocol = 'tcp'
    if protocol == 'tcp':
        packet = IP(src=src, dst=dst)/TCP(flags=flags, sport=sport, dport=dport)
    elif protocol == 'udp':
        if flags: raise ArgumentError("cannot specify flags for udp")
        packet = IP(src=src, dst=dst)/UDP(sport=sport, dport=dport)
    else:
        raise ArgumentError("unknown protocol %s" % protocol)
    if data: packet = packet/data
    old_verbosity = conf.verb
    conf.verb = verbosity
    send(packet, iface=iface)
    conf.verb = old_verbosity

def main(argv=None):
    """Main entry point."""
    if argv is None:
        argv = sys.argv
        try:
            opts, args = getopt.getopt(argv[1:],
                    "d:f:hi:p:v:",
                    ["data=", "flags=", "help", "iface=", "protocol=", "verbosity="])
        except getopt.error, msg:
            usage(msg, 2)
        config = {'protocol':'tcp'}
        for flag, value in opts:
            if flag in ['-d', '--data']:
                config['data'] = value
            elif flag in ['-f', '--flags']:
                config['flags'] = value
            elif flag in ['-h', '--help']:
                usage('', 0)
            elif flag in ['-i', '--iface']:
                config['iface'] = value
            elif flag in ['-p', '--protocol']:
                if value not in ['tcp', 'udp']:
                    usage('unknown protocol %s' % value, 2)
                else:
                    protocol = value
                    config['protocol'] = value
            elif flag in ['-v', '--verbosity']:
                try:
                    config['verbosity'] = int(value)
                except ValueError:
                    usage("invalid verbosity %s (0-3)" % value, 2)
                if config['verbosity'] < 0 or config['verbosity'] > 3:
                    usage("verbosity %s out of range" % value, 2)
            else:
                usage("unknown flag %s" % flag, 2)
        if len(args) < 2:
            usage("not enough arguments: src and dst addresses required", 2)
        if len(args) > 2: 
            usage("too many arguments for src and dst addresses", 2)
        if config['protocol'] == 'udp' and 'flags' in config:
            usage("cannot specify flags with udp", 2)
        config['src'], config['sport'] = parse_address(args[0])
        config['dst'], config['dport'] = parse_address(args[1])
        return ipforge(**config)

if __name__ == '__main__':
    sys.exit(main())

