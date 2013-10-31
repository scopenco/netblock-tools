#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# Author: Andrey Skopenko <andrey@scopenco.net>
'''A tool create rules for Iptables that block or allow networks by country code
(ex: RU CN etc.) For the correct execution of script need to download geip
database and country codes.'''

import csv
import sys
import optparse
import os.path

IPTABLES_BIN = '/sbin/iptables'
MAXMIND_DB = 'http://www.maxmind.com/download/geoip/database/GeoIPCountryCSV.zip'
COUTRY_DB = 'http://www.iso.org/iso/list-en1-semic-3.txt'

def main():
    p = optparse.OptionParser(description=__doc__,
                        prog="netblock",
                        version="0.1",
                        usage="%prog [-cc] [-c] [-i] [-p] [-d] [-a] country1 coutry2 ...")
    p.add_option("--geoipdb",
                        help='Path to GeoIPCountryWhois.csv with GeoIP data',
                        default='GeoIPCountryWhois.csv')
    p.add_option("--countrydb",
                        help='Path to country_names_and_code_elements_txt with country codes', 
                        default='country_names_and_code_elements_txt')
    p.add_option("--cc",
                        action='store_true',
                        help='List of country codes')
    p.add_option("--chain", "-c",
                        help='Iptables chain, default INPUT',
                        default='INPUT')
    p.add_option("--interface", "-i",
                        help='Iptables interface, default eth0',
                        default='eth0')
    p.add_option("--protocol", "-p",
                        help='Iptables protocol, choose from (icmp, tcp, udp, all)',
                        action="store",
                        type="choice",
                        choices=["icmp", "tcp", "udp", 'all'])
    p.add_option('--dport', '-d',
                        help='Iptables destination port')
    p.add_option("--allow_only", "-a",
                        help='Generate iptables rules that allow only selected coutry',
                        action="store_true")
    options, arguments = p.parse_args()

    # show list of country codes
    if options.cc:
        if not os.path.isfile(options.countrydb):
           print '%s not found! try command "wget %s"' % (options.countrydb, COUTRY_DB)
           sys.exit()
        with open(options.countrydb) as f:
            for line in f:
                if line == "" or line.startswith("Country ") or ";" not in line:
                    continue
                c_name, c_code = line.strip().split(";")
                c_name = ' '.join([part.capitalize() for part in \
                        c_name.split(" ")])
                print '%s\t%s' % (c_code, c_name)
        return

    # show help
    if not arguments:
        p.print_help()
        sys.exit()

    if not os.path.isfile(options.geoipdb):
       print '%s not found! try command "wget %s && unzip GeoIPCountryCSV.zip"' % (options.geoipdb, MAXMIND_DB)
       sys.exit()

    # construct iptables rule tempate
    base_rule = IPTABLES_BIN
    if options.chain:
        base_rule += ' -A %s' % options.chain
    if options.interface:
        base_rule += ' -i %s' % options.interface
    if options.protocol:
        base_rule += ' -p %s' % options.protocol
    if options.dport:
        base_rule += ' --dport %s' % options.dport
    if options.allow_only:
        block_rule = base_rule + ' -s %s -j ACCEPT'
    else:
        block_rule = base_rule + ' -s %s -j DROP'

    # get country networks and show iptables rules
    with open(options.geoipdb, 'rb') as f:
        for i in csv.reader(f):
            if i[4] in arguments:
                network = int(i[2])
                mask = int(i[3])
                while (network <= mask):
                    x = 0
                    while True:
                        if network & (1 << x) == 0 and network + ((1 << (x + 1)) - 1) <= mask:
                            x += 1
                            continue
                        print block_rule % '%s/%s' % (get_net(network), 32 - x)
                        break
                    network += 1 << x

    if options.allow_only:
        print base_rule + ' -j DROP'

def get_net(network):
    '''convert bin network to decimal'''
    out = str(network & 255)
    for x in range(3):
        network = network >> 8
        out = '%s.%s' % (str(network & 255), out)
    return out

if __name__ == "__main__":
    main()
