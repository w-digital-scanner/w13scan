#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/6/28 11:03 PM
# @Author  : w8ay
# @File    : plugins.py
import platform
import socket
import sys
import traceback

import requests
import urllib3
from requests import ConnectTimeout, HTTPError, TooManyRedirects, ConnectionError
from urllib3.exceptions import NewConnectionError, PoolError

from W13SCAN import VERSION
from lib.core.common import dataToStdout, createGithubIssue
from lib.core.data import conf
from lib.core.exection import PluginCheckError
from lib.core.output import ResultObject, output
from lib.parse.parse_request import FakeReq
from lib.parse.parse_responnse import FakeResp


class PluginBase(object):

    def __init__(self):
        self.type = None
        self.path = None
        self.target = None
        self.requests: FakeReq = None
        self.response: FakeResp = None

    def new_result(self) -> ResultObject:
        return ResultObject(self)

    def success(self, msg: ResultObject):
        if isinstance(msg, ResultObject):
            msg = msg.output()
        elif isinstance(msg, dict):
            pass
        else:
            raise PluginCheckError('self.success() not ResultObject')
        output.success(msg)

    def checkImplemennted(self):
        name = getattr(self, 'name')
        if not name:
            raise PluginCheckError('name')

    def audit(self):
        raise NotImplementedError

    def execute(self, request: FakeReq, response: FakeResp):
        self.target = ''
        self.requests = request
        self.response = response
        output = None
        try:
            output = self.audit()
        except NotImplementedError:
            msg = 'Plugin: {0} not defined "{1} mode'.format(self.name, 'audit')
            dataToStdout('\r' + msg + '\n\r')

        except (ConnectTimeout, requests.exceptions.ReadTimeout, urllib3.exceptions.ReadTimeoutError, socket.timeout):
            retry = conf.retry
            while retry > 0:
                msg = 'Plugin: {0} timeout, start it over.'.format(self.name)
                if conf["is_debug"]:
                    dataToStdout('\r' + msg + '\n\r')
                try:
                    output = self.audit()
                    break
                except (
                        ConnectTimeout, requests.exceptions.ReadTimeout, urllib3.exceptions.ReadTimeoutError,
                        socket.timeout):
                    retry -= 1
                except Exception:
                    return
            else:
                msg = "connect target '{0}' failed!".format(self.target)
                # Share.dataToStdout('\r' + msg + '\n\r')

        except HTTPError as e:
            msg = 'Plugin: {0} HTTPError occurs, start it over.'.format(self.name)
            # Share.dataToStdout('\r' + msg + '\n\r')
        except ConnectionError:
            msg = "connect target '{0}' failed!".format(self.target)
            # Share.dataToStdout('\r' + msg + '\n\r')
        except requests.exceptions.ChunkedEncodingError:
            pass
        except ConnectionResetError:
            pass
        except TooManyRedirects as e:
            pass
        except NewConnectionError as ex:
            pass
        except PoolError as ex:
            pass
        except UnicodeDecodeError:
            # 这是由于request redirect没有处理编码问题，导致一些网站编码转换被报错,又不能hook其中的关键函数
            # 暂时先pass这个错误
            # refer：https://github.com/boy-hack/w13scan/labels/Requests%20UnicodeDecodeError
            pass
        except UnicodeError:
            # https://github.com/w-digital-scanner/w13scan/issues/238
            # bypass unicode奇葩错误
            pass
        except (
                requests.exceptions.InvalidURL, requests.exceptions.InvalidSchema,
                requests.exceptions.ContentDecodingError):
            # 出现在跳转上的一个奇葩错误，一些网站会在收到敏感操作后跳转到不符合规范的网址，request跟进时就会抛出这个异常
            # refer: https://github.com/boy-hack/w13scan/labels/requests.exceptions.InvalidURL
            # 奇葩的ContentDecodingError
            # refer:https://github.com/boy-hack/w13scan/issues?q=label%3Arequests.exceptions.ContentDecodingError
            pass
        except KeyboardInterrupt:
            raise
        except Exception:
            errMsg = "W13scan plugin traceback:\n"
            errMsg += "Running version: {}\n".format(VERSION)
            errMsg += "Python version: {}\n".format(sys.version.split()[0])
            errMsg += "Operating system: {}\n".format(platform.platform())
            if request:
                errMsg += '\n\nrequest raw:\n'
                errMsg += request.raw
            excMsg = traceback.format_exc()
            if conf.is_debug:
                dataToStdout('\r' + errMsg + '\n\r')
                dataToStdout('\r' + excMsg + '\n\r')
            if createGithubIssue(errMsg, excMsg):
                dataToStdout('\r' + "[x] a issue has reported" + '\n\r')

        return output
