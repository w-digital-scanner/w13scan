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

    def success(self, msg):
        self.collect.append(msg)
        self.log(msg)

    def log(self, msg):
        # Share.dataToStdout(value + '\n')
        Share.dataToStdout('\r' + msg + ' ' * (KB["console_width"][0] - len(msg)) + '\n\r')
        printProgress()


out = OutPut()
