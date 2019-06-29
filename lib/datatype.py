#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/6/29 12:27 AM
# @Author  : w8ay
# @File    : datatype.py
import threading
import logging
from urllib.parse import urlparse

from lib.common import dataToStdout

logging.basicConfig(level=logging.INFO,
                    format='[%(asctime)s] %(levelname)s %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')


class _ThreaData(threading.local):

    def __init__(self):
        self.logger = logging
        self.dataToStdout = dataToStdout
        self.urls = dict()

    def add_url(self, domain):
        p = urlparse(domain)
        if p.netloc not in self.urls:
            self.urls[p.netloc] = set()
        self.urls[p.netloc].add(domain)

    def in_url(self, domain):
        p = urlparse(domain)
        if p.netloc not in self.urls:
            return False
        return domain in self.urls[p.netloc]
