import os
import threading

from lib.baseproxy import AsyncMitmProxy
from lib.controller import start
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
        baseproxy = AsyncMitmProxy(server_addr=('127.0.0.1', 7778), https=True)
        baseproxy.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] User quit")
        exit(0)


if __name__ == '__main__':
    main()
