#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/23 10:30 PM
# @Author  : w8ay
# @File    : __init__.py.py
import copy

from lib.core.option import init
from lib.helper.function import isJavaObjectDeserialization, isPHPObjectDeserialization, isPythonObjectDeserialization
from lib.core.plugins import PluginBase
from lib.core.output import ResultObject
from lib.core.enums import WEB_PLATFORM, PLACE, HTTPMETHOD, VulType
from lib.core.data import conf, KB, path, logger
from lib.core.common import generateResponse
from lib.parse.parse_request import FakeReq
from lib.parse.parse_responnse import FakeResp
from lib.controller.controller import task_push_from_name, task_push, start
from w13scan import modulePath
import requests

__all__ = [
    'isJavaObjectDeserialization', 'isPHPObjectDeserialization', 'isPythonObjectDeserialization',
    'PluginBase', 'ResultObject', 'WEB_PLATFORM', 'conf', 'KB',
    'path', 'logger', 'PLACE', 'HTTPMETHOD', 'VulType', 'generateResponse', 'task_push_from_name', 'task_push', 'start',
]


def scan(url, module_name, conf={}, headers={}):
    root = modulePath()
    cmdline = {
        "level": 5
    }
    cmdline.update(conf)
    init(root, cmdline)
    r = requests.get(url, headers=headers)
    req = FakeReq(url, headers, HTTPMETHOD.GET)
    resp = FakeResp(r.status_code, r.content, r.headers)

    poc_module = copy.deepcopy(KB["registered"][module_name])
    poc_module.execute(req, resp)
