import os
import sys
import threading

from colorama import deinit

try:
    from W13SCAN import VERSION
except ImportError:
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir)))
from W13SCAN.lib.baseproxy import AsyncMitmProxy
from W13SCAN.lib.cmdparse import cmd_line_parser
from W13SCAN.lib.controller import start
from W13SCAN.lib.data import conf, logger
from W13SCAN.lib.option import init


def main():
    # python version check
    if sys.version.split()[0] < "3.6":
        logger.error(
            "incompatible Python version detected ('{}'). To successfully run sqlmap you'll have to use version >= 3.6 (visit 'https://www.python.org/downloads/')".format(
                sys.version.split()[0]))
        sys.exit()
    # init
    root = os.path.dirname(os.path.abspath(__file__))
    cmdline = cmd_line_parser().__dict__
    init(root, cmdline)
    if conf["show_version"]:
        exit()

    # 启动漏洞扫描器
    scanner = threading.Thread(target=start)
    scanner.setDaemon(True)
    scanner.start()

    # 启动代理服务器
    baseproxy = AsyncMitmProxy(server_addr=conf["server_addr"], https=True)

    try:
        baseproxy.serve_forever()
    except KeyboardInterrupt:
        scanner.join(0.1)
        threading.Thread(target=baseproxy.shutdown, daemon=True).start()
        deinit()
        print("\n[*] User quit")
    baseproxy.server_close()


if __name__ == '__main__':
    main()
