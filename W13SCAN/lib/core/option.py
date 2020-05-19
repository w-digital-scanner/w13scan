#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/6/29 1:28 PM
# @Author  : w8ay
# @File    : option.py
import os
import threading
import time
from queue import Queue

from colorama import init as cinit
from cowpy.cow import milk_random_cow

from config import DEBUG, EXCLUDES, THREAD_NUM, LEVEL, \
    TIMEOUT, \
    RETRY, PROXY_CONFIG, PROXY_CONFIG_BOOL, DISABLE, ABLE, XSS_LIMIT_CONTENT_TYPE
from lib.core.common import dataToStdout, ltrim, random_colorama
from lib.core.data import path, KB, logger, conf
from lib.core.exection import PluginCheckError
from lib.core.loader import load_file_to_module
from lib.core.output import OutPut
from lib.core.settings import VERSION
from lib.core.spiderset import SpiderSet
from thirdpart.console import getTerminalSize
from thirdpart.requests import patch_all


def setPaths(root):
    path.root = root
    path.certs = os.path.join(root, 'certs')
    path.scanners = os.path.join(root, 'scanners')
    path.data = os.path.join(root, "data")
    path.fingprints = os.path.join(root, "fingprints")
    path.output = os.path.join(root, "output")


def initKb():
    KB['continue'] = False  # 线程一直继续
    KB['registered'] = dict()  # 注册的漏洞插件列表
    KB['fingerprint'] = dict()  # 注册的指纹插件列表
    KB['task_queue'] = Queue()  # 初始化队列
    KB["spiderset"] = SpiderSet()  # 去重复爬虫
    KB["console_width"] = getTerminalSize()  # 控制台宽度
    KB['start_time'] = time.time()  # 开始时间
    KB["lock"] = threading.Lock()  # 线程锁
    KB["output"] = OutPut()
    KB["running_plugins"] = dict()

    KB['finished'] = 0  # 完成数量
    KB["result"] = 0  # 结果数量
    KB["running"] = 0  # 正在运行数量


def initPlugins():
    # 加载检测插件
    for root, dirs, files in os.walk(path.scanners):
        files = filter(lambda x: not x.startswith("__") and x.endswith(".py"), files)
        for _ in files:
            q = os.path.splitext(_)[0]
            if conf.able and q not in conf.able and q != 'loader':
                continue
            if conf.disable and q in conf.disable:
                continue
            filename = os.path.join(root, _)
            mod = load_file_to_module(filename)
            try:
                mod = mod.W13SCAN()
                mod.checkImplemennted()
                plugin = os.path.splitext(_)[0]
                plugin_type = os.path.split(root)[1]
                relative_path = ltrim(filename, path.root)
                if getattr(mod, 'type', None) is None:
                    setattr(mod, 'type', plugin_type)
                if getattr(mod, 'path', None) is None:
                    setattr(mod, 'path', relative_path)
                KB["registered"][plugin] = mod
            except PluginCheckError as e:
                logger.error('Not "{}" attribute in the plugin:{}'.format(e, filename))
            except AttributeError:
                logger.error('Filename:{} not class "{}"'.format(filename, 'W13SCAN'))
    logger.info('Load scanner plugins:{}'.format(len(KB["registered"])))

    # 加载指纹识别插件
    num = 0
    for root, dirs, files in os.walk(path.fingprints):
        files = filter(lambda x: not x.startswith("__") and x.endswith(".py"), files)
        for _ in files:
            filename = os.path.join(root, _)
            if not os.path.exists(filename):
                continue
            name = os.path.split(os.path.dirname(filename))[-1]
            mod = load_file_to_module(filename)

            if not getattr(mod, 'fingerprint'):
                logger.error("filename:{} load faild,not function 'fingerprint'".format(filename))
                continue
            if name not in KB["fingerprint"]:
                KB["fingerprint"][name] = []
            KB["fingerprint"][name].append(mod)
            num += 1

    logger.info('Load fingerprint plugins:{}'.format(num))


def _init_conf():
    conf.version = False
    conf.debug = DEBUG
    conf.level = LEVEL
    conf.server_addr = None
    conf.url = None
    conf.url_file = None
    conf.proxy = PROXY_CONFIG
    conf.proxy_config_bool = PROXY_CONFIG_BOOL
    conf.timeout = TIMEOUT
    conf.retry = RETRY
    conf.html = False
    conf.json = False
    conf.threads = THREAD_NUM
    conf.disable = DISABLE
    conf.able = ABLE
    # not in cmd parser params
    conf.excludes = EXCLUDES
    conf.XSS_LIMIT_CONTENT_TYPE = XSS_LIMIT_CONTENT_TYPE


def _merge_options(input_options):
    """
    Merge command line options with configuration file and default options.
    """
    if hasattr(input_options, "items"):
        input_options_items = input_options.items()
    else:
        input_options_items = input_options.__dict__.items()

    for key, value in input_options_items:
        # if key not in conf or not value:
        if key not in conf:
            conf[key] = value
        else:
            _ = conf[key]
            if not _:
                conf[key] = value


def _set_conf():
    # show version
    if conf.version:
        exit()

    # server_addr
    if isinstance(conf["server_addr"], str):
        defaulf = 7778
        if ":" in conf["server_addr"]:
            splits = conf["server_addr"].split(":", 2)
            conf["server_addr"] = tuple([splits[0], int(splits[1])])
        else:
            conf["server_addr"] = tuple([conf["server_addr"], defaulf])

    # threads
    conf["threads"] = int(conf["threads"])

    # proxy
    if isinstance(conf["proxy"], str) and "@" in conf["proxy"]:
        conf["proxy_config_bool"] = True
        method, ip = conf["proxy"].split("@")
        conf["proxy"] = {
            method: ip
        }


def _init_stdout():
    # 不扫描网址
    if len(conf["excludes"]):
        logger.info("No scanning:{}".format(repr(conf["excludes"])))
    # 指定扫描插件
    if conf.able:
        logger.info("Use plugins:{}".format(repr(conf.able)))
    # 指定使用插件
    if conf.disable:
        logger.info("Not use plugins:{}".format(repr(conf.disable)))
    logger.info("Level of contracting: [#{}]".format(conf.level))
    if conf.html:
        logger.info("Html will be saved in '{}'".format(KB.output.get_html_filename()))
    logger.info("Result will be saved in '{}'".format(KB.output.get_filename()))


def init(root, cmdline):
    cinit(autoreset=True)
    setPaths(root)
    banner()
    _init_conf()  # 从config.py读取配置信息
    _merge_options(cmdline)  # 从cmdline读取配置
    _set_conf()
    initKb()
    initPlugins()
    _init_stdout()
    patch_all()


def banner():
    msg = "w13scan v{}".format(VERSION)
    sfw = True
    s = milk_random_cow(msg, sfw=sfw)
    dataToStdout(random_colorama(s) + "\n\n")
