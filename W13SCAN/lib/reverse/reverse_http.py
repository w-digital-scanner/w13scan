#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2020/4/5 12:33 AM
# @File    : reverse_http.py
import json
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

from config import REVERSE_HTTP_PORT, REVERSE_HTTP_IP
from lib.reverse.lib import reverse_records, reverse_lock, rlog


class testHTTPServer_RequestHandler(BaseHTTPRequestHandler):
    # GET
    def do_GET(self):
        querypath = urlparse(self.path)
        path, query = querypath.path.lstrip('/'), querypath.query
        client_ip = self.client_address[0]
        content = b"ok"

        if not path:
            return self.output(b'faild')

        if self.path.startswith("/_/search"):
            querys = query.split("=")
            if len(querys) != 2:
                return self.output(b"faild")
            # 寻找接口
            query = querys[1]
            result = []
            reverse_lock.acquire()
            for item in reverse_records:
                item_query = item["query"]
                if query in item_query or query == 'all':
                    result.append(item)
            if result:
                rlog.info("interface result:{}".format(json.dumps(result)))
            reverse_lock.release()
            return self.output(json.dumps(result).encode())

        # insert
        res = {"type": "http", "client": client_ip, "query": self.path, "info": path,
               "time": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))}
        reverse_lock.acquire()
        reverse_records.append(res)
        rlog.info("http insert {}".format(json.dumps(res)))
        reverse_lock.release()
        return self.output(content)

    def log_message(self, format, *args):
        pass

    def output(self, content: bytes):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(content)
        return True


def http_start():
    port = REVERSE_HTTP_PORT
    server_address = (REVERSE_HTTP_IP, port)
    httpd = HTTPServer(server_address, testHTTPServer_RequestHandler)
    rlog.info('Running Server... visited http://{}:{}'.format(REVERSE_HTTP_IP, REVERSE_HTTP_PORT))
    httpd.serve_forever()
