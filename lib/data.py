#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/6/28 12:47 PM
# @Author  : w8ay
# @File    : data.py
import logging

from lib.datatype import _ThreaData

logging.basicConfig(level=logging.INFO,
                    format='[%(asctime)s] %(levelname)s %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')

logger = logging
PATH = dict()  # 全局路径
KB = dict()
Share = _ThreaData()
conf = dict()
