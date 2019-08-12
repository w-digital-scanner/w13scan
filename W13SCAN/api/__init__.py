#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/23 10:30 PM
# @Author  : w8ay
# @File    : __init__.py.py
import copy
import os
import threading
import time

import requests

from W13SCAN.lib.const import Level
from W13SCAN.lib.controller import run_threads, printProgress
from W13SCAN.lib.data import KB, conf
from W13SCAN.lib.option import init
from W13SCAN.plugins.loader import FakeReq, FakeResp
from queue import Queue


class Scanner(object):

    def __init__(self, **kwargs):
        self.url_queue = Queue()
        root = os.path.dirname(os.path.abspath(os.path.join(__file__, os.path.pardir)))
        init(root, kwargs)

    def _task_run(self):
        while not KB["task_queue"].empty() or not self.url_queue.empty():
            poc_module_name, request, response = KB["task_queue"].get()
            KB["lock"].acquire()
            KB["running"] += 1
            KB["lock"].release()
            poc_module = copy.deepcopy(KB["registered"][poc_module_name])

            poc_module.execute(request, response)

            KB["lock"].acquire()
            KB["finished"] += 1
            KB["running"] -= 1
            KB["lock"].release()
            printProgress()
        printProgress()

    def custom_url(self):
        while not self.url_queue.empty():
            url = self.url_queue.get()
            self.put(url)

    def run(self):
        if not self.url_queue.empty():
            thread = threading.Thread(target=self.custom_url, )
            thread.setDaemon(True)
            thread.start()
            time.sleep(5)
        run_threads(conf["threads"], self._task_run)
        # scanner = threading.Thread(target=self._start)
        # scanner.setDaemon(True)
        # scanner.start()

    def put_nodelay(self, url):
        self.url_queue.put(url)

    def put(self, url):
        headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.142 Safari/538"
        }
        try:
            r = requests.get(url, headers=headers)
        except:
            return
        # print(r.status_code,len(r.text))
        req = FakeReq(url, headers)
        resp = FakeResp(r)
        KB['task_queue'].put(('loader', req, resp))


__all__ = (
    Level, Scanner
)
