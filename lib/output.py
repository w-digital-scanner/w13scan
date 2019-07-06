#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/6/29 2:28 PM
# @Author  : w8ay
# @File    : output.py

from lib.controller import printProgress
from lib.data import Share, KB


class OutPut(object):

    def __init__(self):
        self.collect = []

    def success(self, url, plugin='unknown', **kw):
        report = {
            "url": url,
            "plugin": plugin
        }
        report.update(kw)
        # msg = ''
        # for k, v in report.items():
        #     msg += "{}:{}  ".format(k, str(v))
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
        while len(msg) > width:
            _ = msg[:width]
            Share.dataToStdout('\r' + _ + '\n\r')
            msg = msg[width:]
        Share.dataToStdout('\r' + msg + '\n\r')
        printProgress()

    def output(self):
        '''
        todo output file
        :return:
        '''
        pass


out = OutPut()
