#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/6/28 11:22 PM
# @Author  : w8ay
# @File    : controller.py
import copy
import threading
import time
import traceback

from lib.core.common import dataToStdout
from lib.core.data import KB, logger, conf


def exception_handled_function(thread_function, args=()):
    try:
        thread_function(*args)
    except KeyboardInterrupt:
        KB["continue"] = False
        raise
    except Exception:
        traceback.print_exc()


def run_threads(num_threads, thread_function, args: tuple = ()):
    threads = []

    try:
        info_msg = "Staring [#{0}] threads".format(num_threads)
        logger.info(info_msg)

        # Start the threads
        for num_threads in range(num_threads):
            thread = threading.Thread(target=exception_handled_function, name=str(num_threads),
                                      args=(thread_function, args))
            thread.setDaemon(True)
            try:
                thread.start()
            except Exception as ex:
                err_msg = "error occurred while starting new thread ('{0}')".format(str(ex))
                logger.critical(err_msg)
                break

            threads.append(thread)

        # And wait for them to all finish
        alive = True
        while alive:
            alive = False
            for thread in threads:
                if thread.isAlive():
                    alive = True
                    time.sleep(0.1)

    except KeyboardInterrupt as ex:
        KB['continue'] = False
        raise

    except Exception as ex:
        logger.error("thread {0}: {1}".format(threading.currentThread().getName(), str(ex)))
        traceback.print_exc()
    finally:
        dataToStdout('\n')


def start():
    run_threads(conf.threads, task_run)


def task_run():
    while KB["continue"] or not KB["task_queue"].empty():
        poc_module_name, request, response = KB["task_queue"].get()
        KB.lock.acquire()
        KB.running += 1
        if poc_module_name not in KB.running_plugins:
            KB.running_plugins[poc_module_name] = 0
        KB.running_plugins[poc_module_name] += 1
        KB.lock.release()
        printProgress()
        poc_module = copy.deepcopy(KB["registered"][poc_module_name])
        poc_module.execute(request, response)
        KB.lock.acquire()
        KB.finished += 1
        KB.running -= 1
        KB.running_plugins[poc_module_name] -= 1
        if KB.running_plugins[poc_module_name] == 0:
            del KB.running_plugins[poc_module_name]

        KB.lock.release()
        printProgress()
    printProgress()
    # TODO
    # set task delay


def printProgress():
    KB.lock.acquire()
    if conf.debug:
        # 查看当前正在运行的插件
        KB.output.log(repr(KB.running_plugins))
    msg = '%d success | %d running | %d remaining | %s scanned in %.2f seconds' % (
        KB.output.count(), KB.running, KB.task_queue.qsize(), KB.finished, time.time() - KB.start_time)

    _ = '\r' + ' ' * (KB['console_width'][0] - len(msg)) + msg
    dataToStdout(_)
    KB.lock.release()


def task_push(plugin_type, request, response):
    for _ in KB["registered"].keys():
        module = KB["registered"][_]
        if module.type == plugin_type:
            KB['task_queue'].put((_, copy.deepcopy(request), copy.deepcopy(response)))


def task_push_from_name(pluginName, req, resp):
    KB['task_queue'].put((pluginName, copy.deepcopy(req), copy.deepcopy(resp)))
