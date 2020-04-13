#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/6/29 2:28 PM
# @Author  : w8ay
# @File    : output.py
import collections
import json
import os
import time
from threading import Lock

from colorama import Fore

from lib.core.common import dataToStdout, md5
from lib.core.data import KB, path, logger
from datetime import datetime


class OutPut(object):

    def __init__(self):
        self.collect = []
        self.lock = Lock()
        self.result_set = set()

        folder_name = datetime.today().strftime("%m_%d_%Y")
        folder_path = os.path.join(path.output, folder_name)
        if not os.path.isdir(folder_path):
            os.mkdir(folder_path)
        filename = str(int(time.time()))
        self.filename = os.path.join(folder_path, filename)
        logger.info("result will be saved in {}".format(self.filename))

    def _set(self, value):
        '''
        存储相同的结果，防止重复,不存在返回真，存在返回假
        :param value:
        :return:
        '''
        if value not in self.result_set:
            self.result_set.add(value)
            return True
        return False

    def count(self):
        self.lock.acquire()
        count = len(self.collect)
        self.lock.release()
        return count

    def success(self, output: dict):
        # 计算去重md5
        md5sum = md5(str(output).encode())
        if not self._set(md5sum):
            return
        self.lock.acquire()
        with open(self.filename, "a+") as f:
            f.write(json.dumps(output) + '\n')
        self.lock.release()
        self.collect.append(output)
        vultype = output["type"]
        url = output["url"]
        result = output["result"]
        msg = "[{type}] {url} {result}".format(type=vultype, url=url, result=result)
        self.log(msg)

    def log(self, msg, color=Fore.YELLOW):
        width = KB["console_width"][0]
        outputs = []
        msgs = msg.split('\n')
        for i in msgs:
            line = i
            while len(line) >= width:
                _ = line[:width]
                outputs.append(_)
                # Share.dataToStdout('\r' + _ + ' ' * (width - len(msg)) + '\n\r')
                line = line[width:]
            outputs.append(line)
        for i in outputs:
            self.lock.acquire()
            dataToStdout('\r' + color + i + ' ' * (width - len(i)) + '\n\r')
            self.lock.release()


class ResultObject(object):
    def __init__(self, baseplugin):
        self.name = baseplugin.name
        self.path = baseplugin.path

        self.url = ""  # 插件url
        self.result = ""  # 插件返回结果
        self.type = ""  # 漏洞类型 枚举
        self.detail = collections.OrderedDict()

    def init_info(self, url, result, vultype):
        self.url = url
        self.result = result
        self.type = vultype

    def add_detail(self, name: str, request: str, response: str, msg: str, param: str, value: str, position: str):
        if name not in self.detail:
            self.detail[name] = []
        self.detail[name].append({
            "request": request,
            "response": response,
            "msg": msg,
            "basic": {
                "param": param,
                "value": value,
                "position": position
            }
        })

    def output(self):
        self.createtime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        return {
            "name": self.name,
            "path": self.path,
            "url": self.url,
            "result": self.result,
            "type": self.type,
            "createtime": self.createtime,
            "detail": self.detail
        }


output = OutPut()
