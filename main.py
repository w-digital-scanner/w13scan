import os
import signal
import threading

from config import SERVER_ADDR
from lib.baseproxy import AsyncMitmProxy
from lib.controller import start
from lib.data import KB
from lib.option import init


def main():
    # init
    root = os.path.dirname(os.path.abspath(__file__))
    init(root)

    try:
        # 启动漏洞扫描器线程
        scanner = threading.Thread(target=start)
        scanner.setDaemon(True)
        scanner.start()

        # 启动代理服务器
        baseproxy = AsyncMitmProxy(server_addr=SERVER_ADDR, https=True)
        baseproxy.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] User quit")
        if not KB["is_win"]:
            os.kill(os.getpid(), signal.SIGHUP)


if __name__ == '__main__':
    main()
