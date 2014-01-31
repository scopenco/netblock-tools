#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# Author: Andrey Skopenko <andrey@scopenco.net>
'''%prog [OPTIONS] <RULES_CONFIG>

Anti DDOS tool used to block ip addresses
in firewall based on access list of web server.

Examples
$ python bin/ipblock.py etc/config -f access_log -d
$ tail -f /var/log/nginx/access.log | python bin/ipblock.py etc/config -f -

All options can be defined in configuration file.
'''

import os
import sys
import re
import logging
import logging.handlers
import IPy
import subprocess
from optparse import OptionParser, make_option


def read_config(path):

    drop_rules = []

    def drop(pattern, mask):
        drop_rules.append((pattern, mask))

    # The above functions are just syntatic sugar for config
    data = dict(drop=drop)
    data['drop_rules'] = drop_rules

    try:
        execfile(path, {}, data)
    except (SyntaxError, OSError, IOError), e:
        logging.critical(e)
        sys.exit(1)

    del data['drop']
    return data
#end def read_config


def open_anything(source):
    if source == "-":
        return sys.stdin

    try:
        return open(source)
    except (OSError, IOError), e:
        logging.critical(e)
        sys.exit(1)
#end def open_anything


def setup_logging(appname, debug=False):
    """ set up logging """

    log_dir = os.path.expanduser("~/.%s" % appname)
    if not os.access(log_dir, os.W_OK):
        try:
            os.makedirs(log_dir)
        except IOError, e:
            raise RuntimeError("Could not create %d directory: " % log_dir), e

    format = '%(asctime)s: %(message)s'
    fileformat = '%(asctime)s ipblock: %(message)s'
    filename = os.path.join(log_dir, appname + ".log")

    # common logging options
    rootLogger = logging.getLogger()
    rootLogger.setLevel(logging.INFO)

    # file logging
    fileHandler = logging.handlers.RotatingFileHandler(filename,
                                                       "a", maxBytes=1024*1024,
                                                       backupCount=5)
    fileHandler.setFormatter(logging.Formatter(fileformat))
    rootLogger.addHandler(fileHandler)

    # stream logging
    streamHandler = logging.StreamHandler(sys.stdout)
    if debug:
        streamHandler.setLevel(logging.DEBUG)
    streamHandler.setFormatter(logging.Formatter(format))
    rootLogger.addHandler(streamHandler)
#end def setup_logging


def main():
    option_list = [
        make_option('-f', '--file', dest='file',
                    help='data file or pipe (-)'),
        make_option('-s', '--show', dest='show',
                    action='count', help='Show only'),
        make_option('-d', '--debug', dest='debug', action='count',
                    help='verbose output (use twice for extra debug)'),
    ]
    parser = OptionParser(usage=__doc__, option_list=option_list)

    options, args = parser.parse_args()

    if not args:
        parser.print_help()
        parser.error('RULES_CONFIG must be specified')

    config_file = args[0]
    # default values
    defaults = dict(file='', command='', pattern='', show=False, debug=False)
    config = dict()
    config.update(defaults)
    # Config file overrides defaults
    config.update(read_config(config_file))
    # Options override config
    config.update(dict([(k, v) for k, v in vars(options).items()
                       if v is not None]))

    # set logging
    debug = config.get('debug')
    setup_logging("ipblock", debug)

    # start
    logging.info('run blocking')
    logging.debug('config: %r', config)
    logging.debug('options: %r', vars(options))

    # get rules
    drop_rules = config.get('drop_rules', [])
    logging.debug('drop_rules: %r', drop_rules)

    # open file for reading
    logging.debug(config.get('file'))
    f = open_anything(config.get('file'))

    regs = []
    for drop_rule, mask in drop_rules:
        # create regext cache
        logging.debug('compile drop rule: %r', drop_rule)
        regs.append((re.compile(drop_rule), mask))

    # compile pattern from config
    ip = re.compile(config.get('pattern'))

    show_only = config.get('show')
    block_command = config.get('command')

    nets = []
    for line in f:
        for reg, ip_mask in regs:
            if reg.match(line):
                block_ip = ip.search(line).group(0)
                block_net = IPy.IP(block_ip).make_net(ip_mask)
                if block_net not in nets:
                    nets.append(block_net)
                    if show_only:
                        print block_command % block_net
                    else:
                        logging.info('blocking %s' % block_net)
                        subprocess.Popen(block_command % block_net, shell=True,
                                         stdout=subprocess.PIPE)
                break

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logging.critical("aborted at user request")
        sys.exit(1)
