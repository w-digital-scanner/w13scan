import os
import signal
import threading

from lib.baseproxy import AsyncMitmProxy
from lib.cmdparse import cmd_line_parser
from lib.controller import start
from lib.data import KB, conf
from lib.option import init, banner


def main():
    # init
    root = os.path.dirname(os.path.abspath(__file__))
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
        if not KB["is_win"]:
            os.kill(os.getpid(), signal.SIGHUP)


if __name__ == '__main__':
    main()
