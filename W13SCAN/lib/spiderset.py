#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/5 4:00 PM
# @Author  : w8ay
# @File    : spiderset.py
import threading

from W13SCAN.lib.common import md5


class SpiderSet(object):
    """
    去重模块简易实现，后期若占用过大会考虑基于文件方式
    """

    def __init__(self):
        self.spider_list = set()
        self.lock = threading.Lock()

    def add(self, netloc, plugin):
        """
        添加成功返回True，添加失败有重复返回False
        :param netloc:
        :param plugin:
        :return:bool
        """
        ret = True
        if not (isinstance(netloc, str) and isinstance(plugin, str)):
            netloc = str(netloc)
            plugin = str(plugin)
        _ = "{}:{}".format(netloc, plugin)
        _ = md5(_.encode('utf-8'))
        self.lock.acquire()
        if _ in self.spider_list:
            ret = False
        else:
            self.spider_list.add(_)
        self.lock.release()
        return ret
