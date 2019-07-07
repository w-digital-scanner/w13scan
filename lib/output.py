#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/6/29 2:28 PM
# @Author  : w8ay
# @File    : output.py

from lib.controller import printProgress
from lib.data import Share, KB
from threading import Lock


class OutPut(object):

    def __init__(self):
        self.collect = []
        self.lock = Lock()

    def success(self, url, plugin='unknown', **kw):
        report = {
            "url": url,
            "plugin": plugin
        }
        report.update(kw)
        self.collect.append(report)
        self.log("[{}]".format(report["plugin"]))
        del report["plugin"]
        for k, v in report.items():
            msg = "{0}{1}{2}".format(k, "   ", str(v))
            self.log(msg)
        self.log(' ')

    def log(self, msg):
        # Share.dataToStdout(value + '\n')
        width = KB["console_width"][0]
        self.lock.acquire()
        while len(msg) > width:
            _ = msg[:width]
            Share.dataToStdout('\r' + _ + '\n\r')
            msg = msg[width:]
        Share.dataToStdout('\r' + msg + '\n\r')
        self.lock.release()
        printProgress()

    def output(self):
        '''
        todo output file
        :return:
        '''
        pass


out = OutPut()
