#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/23 10:30 PM
# @Author  : w8ay
# @File    : __init__.py.py
import copy
import os

import requests

from W13SCAN.lib.const import Level
from W13SCAN.lib.controller import run_threads, printProgress
from W13SCAN.lib.data import KB, conf
from W13SCAN.lib.option import init
from W13SCAN.plugins.loader import FakeReq, FakeResp


class Scanner(object):

    def __init__(self, **kwargs):
        root = os.path.dirname(os.path.abspath(os.path.join(__file__, os.path.pardir)))
        init(root, kwargs)

    def _task_run(self):
        while not KB["task_queue"].empty():
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

    def run(self):
        run_threads(conf["threads"], self._task_run)
        # scanner = threading.Thread(target=self._start)
        # scanner.setDaemon(True)
        # scanner.start()

    def put(self, url):
        headers = {

        }
        r = requests.get(url, headers=headers)
        req = FakeReq(url, headers)
        resp = FakeResp(r)
        KB['task_queue'].put(('loader', req, resp))


__all__ = (
    Level, Scanner
)
