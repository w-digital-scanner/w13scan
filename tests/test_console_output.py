#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/8/4 4:09 PM
# @Author  : w8ay
# @File    : test_console_output.py
import time
import unittest

from W13SCAN.lib.controller import printProgress
from W13SCAN.lib.output import OutPut, KB
from W13SCAN.thirdpart.console import getTerminalSize
from queue import Queue


class TestCase(unittest.TestCase):
    def setUp(self):
        self.output = OutPut()
        KB["console_width"] = getTerminalSize()
        KB["task_queue"] = Queue()
        KB["finished"] = 100
        KB["start_time"] = time.time()
        print(KB)

    def tearDown(self):
        pass

    def test_console_output(self):
        self.output.log("test")
        for i in range(100):
            time.sleep(0.2)
            printProgress()


if __name__ == '__main__':
    unittest.main()
