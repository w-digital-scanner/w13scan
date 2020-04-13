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

from config import EXCLUDE_PLUGINS, INCLUDE_PLUGINS, SERVER_ADDR, DEBUG, INCLUDES, EXCLUDES, THREAD_NUM, LEVEL, \
    TIMEOUT, \
    RETRY, PROXY_CONFIG, ACTIVE_SCAN, PROXY_CONFIG_BOOL
from lib.core.common import dataToStdout, ltrim
from lib.core.data import path, KB, logger, conf
from lib.core.exection import PluginCheckError
from lib.core.loader import load_file_to_module
from lib.core.spiderset import SpiderSet
from thirdpart.console import getTerminalSize
from thirdpart.requests import patch_all


def setPaths(root):
    path.root = root
    path.certs = os.path.join(root, 'certs')
    path.plugins = os.path.join(root, 'plugins')
    path.data = os.path.join(root, "data")
    path.fingprints = os.path.join(root, "fingprints")
    path.output = os.path.join(root, "output")


def initKb():
    KB['continue'] = True  # 线程是否继续
    KB['registered'] = dict()  # 注册的漏洞插件列表
    KB['fingerprint'] = dict()  # 注册的指纹插件列表
    KB['task_queue'] = Queue()  # 初始化队列
    KB["spiderset"] = SpiderSet()  # 去重复爬虫
    KB["console_width"] = getTerminalSize()  # 控制台宽度
    KB['start_time'] = time.time()  # 开始时间
    KB["lock"] = threading.Lock()  # 线程锁

    KB['finished'] = 0  # 完成数量
    KB["result"] = 0  # 结果数量
    KB["running"] = 0  # 正在运行数量


def initPlugins():
    # 加载检测插件
    for root, dirs, files in os.walk(path.plugins):
        files = filter(lambda x: not x.startswith("__") and x.endswith(".py"), files)
        for _ in files:
            if len(INCLUDE_PLUGINS) == 1 and INCLUDE_PLUGINS[0] == 'all':
                pass
            else:
                if "loader.py" not in INCLUDE_PLUGINS:
                    INCLUDE_PLUGINS.append("loader.py")
                if _ not in INCLUDE_PLUGINS:
                    continue
            if _ in EXCLUDE_PLUGINS:
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
    logger.info('load plugin:{}'.format(len(KB["registered"])))

    # 加载指纹识别插件
    num = 0
    for root, dirs, files in os.walk(path.fingprints):
        files = filter(lambda x: not x.startswith("__") and x.endswith(".py"), files)
        for _ in files:
            filename = os.path.join(root, _)
            if not os.path.exists(filename):
                continue
            name = os.path.dirname(filename).split("/")[-1]
            mod = load_file_to_module(filename)

            if not getattr(mod, 'fingerprint'):
                logger.error("filename:{} load faild,not function 'fingerprint'".format(filename))
                continue
            if name not in KB["fingerprint"]:
                KB["fingerprint"][name] = []
            KB["fingerprint"][name].append(mod)
            num += 1

    logger.info('load fingerprint plugin:{}'.format(num))


def _setConfAttributes():
    conf.show_version = False
    conf.is_debug = False
    conf.level = 1
    conf.url = None
    conf.url_file = None
    conf.server_addr = None
    conf.proxy = None
    conf.timeout = 30
    conf.retry = 2
    conf.threads = 21
    conf.excludes = []
    conf.includes = []
    conf.exclude_plugins = []
    conf.include_plugins = []
    conf.no_active = False
    conf.proxy_config_bool = False


def _init_conf():
    conf["is_debug"] = DEBUG
    conf["server_addr"] = SERVER_ADDR
    conf["threads"] = THREAD_NUM
    conf["excludes"] = EXCLUDES
    conf["includes"] = INCLUDES
    conf["exclude_plugins"] = EXCLUDE_PLUGINS
    conf["include_plugins"] = INCLUDE_PLUGINS
    conf["retry"] = RETRY
    conf["timeout"] = TIMEOUT
    conf["level"] = LEVEL
    conf["no_active"] = ACTIVE_SCAN
    conf["proxy"] = PROXY_CONFIG
    conf["proxy_config_bool"] = PROXY_CONFIG_BOOL


def _merge_options(input_options):
    """
    Merge command line options with configuration file and default options.
    """
    if hasattr(input_options, "items"):
        input_options_items = input_options.items()
    else:
        input_options_items = input_options.__dict__.items()

    for key, value in input_options_items:
        if key not in conf or value not in (None, False):
            conf[key] = value


def _set_conf():
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

    # conf["excludes"] = EXCLUDES
    # conf["includes"] = INCLUDES
    # conf["exclude_plugins"] = EXCLUDE_PLUGINS
    # conf["include_plugins"] = INCLUDE_PLUGINS

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
        logger.info("Exclude urls:{}".format(repr(conf["excludes"])))
    # 指定扫描网址
    if len(conf["includes"]) and conf["includes"][0] != ".*":
        logger.info("Include urls:{}".format(repr(conf["includes"])))
    # 不使用插件
    if len(conf["exclude_plugins"]):
        logger.info("Exclude plugins:{}".format(repr(conf["exclude_plugins"])))
    # 指定使用插件
    if len(conf["include_plugins"]) and conf["include_plugins"][0] != "all":
        logger.info("Include plugins:{}".format(repr(conf["include_plugins"])))
    # 主动探测
    no_active = 'On' if str(conf["no_active"]) == "True" else "Off"
    logger.info("Active detection mode:{}".format(no_active))


def init(root, cmdline):
    cinit(autoreset=True)
    setPaths(root)
    banner()
    _setConfAttributes()
    # 从config.py读取配置信息
    _init_conf()
    # 从cmdline读取配置
    _merge_options(cmdline)
    _set_conf()
    initKb()
    initPlugins()
    _init_stdout()
    patch_all()


def banner():
    banner = open(os.path.join(path.data, "logo.txt"), "rb").read().decode("unicode_escape")
    dataToStdout(banner)
