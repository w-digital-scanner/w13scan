import os

from lib.baseproxy import AsyncMitmProxy, InterceptPlug, Request, Response
from lib.controller import start
from lib.data import PATH, KB, Share
from lib.loader import load_file_to_module
from thirdpart.requests import patch_all
from queue import Queue
import threading


class DebugInterceptor(InterceptPlug):
    def deal_request(self, request: Request, response: Response):
        # print(request.path)
        # print(request.get_headers())
        # print(request.get_body_data())
        print(request.to_data().decode())
        # print(response.get_body_str())
        print(response.get_body_str())
        print(response.get_body_data())


def main():
    # init
    root = os.path.dirname(os.path.abspath(__file__))
    PATH['root'] = root
    PATH['certs'] = os.path.join(root, 'certs')
    PATH['plugins'] = os.path.join(root, 'plugins')

    KB['continue'] = True
    KB['registered'] = dict()
    KB['task_queue'] = Queue()

    patch_all()

    # 加载所有插件
    _plugins = []
    for root, dirs, files in os.walk(PATH['plugins']):
        files = filter(lambda x: not x.startswith("__") and x.endswith(".py"), files)
        for _ in files:
            filename = os.path.join(PATH['plugins'], _)
            mod = load_file_to_module(filename)
            try:
                mod = mod.W13SCAN()
                KB["registered"][_] = mod
            except AttributeError:
                Share.logger.error('Filename :{} not class "{}"'.format(_, 'W13SCAN'))

    try:
        # 启动漏洞扫描器线程
        scanner = threading.Thread(target=start)
        scanner.start()

        # 启动代理服务器
        baseproxy = AsyncMitmProxy(server_addr=('127.0.0.1', 7778), https=True)
        baseproxy.register(DebugInterceptor)
        baseproxy.serve_forever()
    except KeyboardInterrupt:
        print("[*] User quit")
        raise
        # exit(0)


if __name__ == '__main__':
    main()
