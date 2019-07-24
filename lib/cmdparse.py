#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/24 10:25 AM
# @Author  : w8ay
# @File    : cmdparse.py
import argparse
import os
import sys


def cmd_line_parser(argv=None):
    """
    This function parses the command line parameters and arguments
    """

    if not argv:
        argv = sys.argv

    _ = os.path.basename(argv[0])
    usage = "w13scan [options]"
    parser = argparse.ArgumentParser(prog='W13Scan', usage=usage)

    parser.add_argument("--version", dest="show_version", action="store_true",
                        help="Show program's version number and exit")

    parser.add_argument("--debug", dest="is_debug", action="store_true",
                        help="Show program's version number and exit")
    parser.add_argument("-v", dest="verbose", type=int, default=1, choices=list(range(7)),
                        help="Verbosity level: 0-6 (default 1)")

    # Target options
    target = parser.add_argument_group('Target', "At least one of these "
                                                 "options has to be provided to define the target(s)")
    target.add_argument("-u", "--url", dest="url",
                        help="Target URL (e.g. \"http://www.site.com/vuln.php?id=1\")")

    target.add_argument("-f", "--file", dest="url_file", help="Scan multiple targets given in a textual file")
    target.add_argument("-s", "--server-addr", dest="server_addr", help="server addr (ip:port)")

    # Requests options
    request = parser.add_argument_group("Request", "Network request options")
    request.add_argument("--proxy", dest="proxy", help="Use a proxy to connect to the target URL")
    request.add_argument("--timeout", dest="timeout", help="Seconds to wait before timeout connection (default 30)",
                         type=int, default=30)
    request.add_argument("--retry", dest="retry", default=False, help="Time out retrials times.")

    # Optimization options
    optimization = parser.add_argument_group("Optimization", "Optimization options")
    optimization.add_argument("--threads", dest="threads", type=int, default=21,
                              help="Max number of concurrent network requests (default 1)")
    optimization.add_argument("-e", dest="excludes", nargs='+',
                              help="exclude urls")
    optimization.add_argument("-i", dest="includes", nargs='+',
                              help="include urls")
    optimization.add_argument("-ep", dest="exclude_plugins", nargs='+',
                              help="exclude plugins")
    optimization.add_argument("-ip", dest="include_plugins", nargs='+',
                              help="include plugins")

    args = parser.parse_args()
    return args
