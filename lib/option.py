#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/6/29 1:28 PM
# @Author  : w8ay
# @File    : option.py
import os

from config import VERSION, REPOSITORY
from lib.common import dataToStdout
from lib.data import PATH, KB, Share
from lib.loader import load_file_to_module
from thirdpart.requests import patch_all
from queue import Queue


def _set_path(root):
    PATH['root'] = root
    PATH['certs'] = os.path.join(root, 'certs')
    PATH['plugins'] = os.path.join(root, 'plugins')


def _init_kb():
    KB['continue'] = True
    KB['registered'] = dict()
    KB['task_queue'] = Queue()


def _init_plugins():
    # 加载所有插件
    _plugins = []
    for root, dirs, files in os.walk(PATH['plugins']):
        files = filter(lambda x: not x.startswith("__") and x.endswith(".py"), files)
        for _ in files:
            filename = os.path.join(PATH['plugins'], _)
            mod = load_file_to_module(filename)
            try:
                mod = mod.W13SCAN()
                KB["registered"][_] = mod
            except AttributeError:
                Share.logger.error('Filename:{} not class "{}"'.format(_, 'W13SCAN'))


def init(root):
    banner()
    _set_path(root)
    _init_kb()
    _init_plugins()
    patch_all()


def banner():
    _ = r'''
    ❤️ (  ⚫︎ー⚫︎  ) Woo,W13Scan~
    　／　　　   ＼      
     /　　　  ○ 　\   Version:{version}   
    /　 /  　  ヽ  \   
    |　/　 　　　\　|   
     \Ԏ　         |イ  
    　卜−　　   ―イ   
    　 \　 /\　 /
    　　 ︶　 ︶
'''
    dataToStdout(_.format(version=VERSION, git=REPOSITORY))
