import inspect
import os
import sys
import threading

from colorama import deinit

from lib.controller.controller import start
from lib.proxy.baseproxy import AsyncMitmProxy

try:
    from . import VERSION
except ImportError:
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir)))
from lib.parse.cmdparse import cmd_line_parser
from lib.core.data import logger, conf
from lib.core.option import init


def version_check():
    if sys.version.split()[0] < "3.6":
        logger.error(
            "incompatible Python version detected ('{}'). To successfully run sqlmap you'll have to use version >= 3.6 (visit 'https://www.python.org/downloads/')".format(
                sys.version.split()[0]))
        sys.exit()


def modulePath():
    """
    This will get us the program's directory, even if we are frozen
    using py2exe
    """

    try:
        _ = sys.executable if hasattr(sys, "frozen") else __file__
    except NameError:
        _ = inspect.getsourcefile(modulePath)

    return os.path.dirname(os.path.realpath(_))


def main():
    version_check()

    # init
    root = modulePath()
    cmdline = cmd_line_parser()
    init(root, cmdline)

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
