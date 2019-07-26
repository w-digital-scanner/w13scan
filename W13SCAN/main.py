import os
import signal
import sys
import threading

from colorama import deinit, init as cinit

try:
    import W13SCAN
except ImportError:
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir)))

from W13SCAN.lib.baseproxy import AsyncMitmProxy
from W13SCAN.lib.cmdparse import cmd_line_parser
from W13SCAN.lib.controller import start
from W13SCAN.lib.data import KB, conf
from W13SCAN.lib.option import init, banner


def main():
    # init
    root = os.path.dirname(os.path.abspath(__file__))
    cinit(autoreset=True)
    banner()

    cmdline = cmd_line_parser().__dict__
    init(root, cmdline)
    if conf["show_version"]:
        exit()

    try:
        # 启动漏洞扫描器
        scanner = threading.Thread(target=start)
        scanner.setDaemon(True)
        scanner.start()

        # 启动代理服务器
        SERVER_ADDR = conf["server_addr"]
        baseproxy = AsyncMitmProxy(server_addr=SERVER_ADDR, https=True)
        baseproxy.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] User quit")
        deinit()
        if not KB["is_win"]:
            os.kill(os.getpid(), signal.SIGHUP)


if __name__ == '__main__':
    main()
