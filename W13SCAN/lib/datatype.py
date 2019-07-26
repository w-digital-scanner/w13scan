#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/6/29 12:27 AM
# @Author  : w8ay
# @File    : datatype.py
import logging
import threading

from W13SCAN.lib.common import dataToStdout


class _ThreaData(object):

    def __init__(self):
        self.logger = logging
        self.lock = threading.Lock()
        self.urls = dict()

    def dataToStdout(self, msg):
        self.lock.acquire()
        dataToStdout(msg)
        self.lock.release()
