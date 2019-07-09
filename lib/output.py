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
        raw = None
        if "raw" in report:
            if isinstance(report['raw'], str):
                raw = [report['raw']]
            elif isinstance(report['raw'],list):
                raw = report['raw']
            del report['raw']
        for k, v in report.items():
            msg = "{0}{1}{2}".format(k, " " * (15 - len(k)), str(v).strip())
            self.log(msg)
        self.log(' ')
        if raw:
            index = 0
            for i in raw:
                self.log("#{0} 请求包".format(index))
                self.log(i)
                self.log(" ")
                index += 1
        self.lock.release()
        printProgress()

    def log(self, msg):
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
            Share.dataToStdout('\r' + i + ' ' * (width - len(i)) + '\n\r')

    def output(self):
        '''
        todo output file
        :return:
        '''
        pass


out = OutPut()
