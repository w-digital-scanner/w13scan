#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/6/29 2:28 PM
# @Author  : w8ay
# @File    : output.py

from lib.controller import printProgress
from lib.data import Share


class OutPut(object):

    def __init__(self):
        self.collect = []

    def success(self, url, plugin='unknown', **kw):
        report = {
            "url": url,
            "plugin": plugin
        }
        report.update(kw)
        msg = ''
        for k, v in report.items():
            msg += "{}:{}  ".format(k, str(v))
        self.collect.append(report)
        self.log(msg)

    def log(self, msg):
        # Share.dataToStdout(value + '\n')
        Share.dataToStdout('\r' + msg + '\n\r')
        printProgress()


out = OutPut()
