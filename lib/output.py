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
        self.lock.acquire()
        self.collect.append(report)
        self.log("[{}] ".format(report["plugin"]))
        del report["plugin"]
        for k, v in list(report.items()):
            msg = "{0}{1}{2}".format(k, " " * (15 - len(k)), str(v).strip())
            self.log(msg)
        self.log(' ')
        self.lock.release()
        printProgress()

    def log(self, msg):
        width = KB["console_width"][0]
        while len(msg) >= width:
            _ = msg[:width]
            Share.dataToStdout('\r' + _ + ' ' * (width - len(msg)) + '\n\r')
            msg = msg[width:]
        Share.dataToStdout('\r' + msg + ' ' * (width - len(msg)) + '\n\r')

    def output(self):
        '''
        todo output file
        :return:
        '''
        pass


out = OutPut()
