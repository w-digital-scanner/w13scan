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
from W13SCAN.lib.baseproxy import Request, Response
from W13SCAN.lib.common import createGithubIssue, dataToStdout
from W13SCAN.lib.data import Share, conf


class PluginBase(object):

    def __init__(self):
        self.type = None
        self.target = None
        self.requests: Request = None
        self.response: Response = None

    def audit(self):
        raise NotImplementedError

    def build_url(self):
        netloc = "http"
        if self.requests.https:
            netloc = "https"
        if (netloc == "https" and int(self.requests.port) == 443) or (
                netloc == "http" and int(self.requests.port) == 80):
            url = "{0}://{1}{2}".format(netloc, self.requests.hostname, self.requests.path)
        else:
            url = "{0}://{1}:{2}{3}".format(netloc, self.requests.hostname, self.requests.port, self.requests.path)
        return url

    def execute(self, request: Request, response: Response):
        self.target = ''
        self.requests = request
        self.response = response
        output = None
        try:
            output = self.audit()
        except NotImplementedError:
            msg = 'Plugin: {0} not defined "{1} mode'.format(self.name, 'audit')
            Share.dataToStdout(Share.dataToStdout('\r' + msg + '\n\r'))

        except (ConnectTimeout, requests.exceptions.ReadTimeout, urllib3.exceptions.ReadTimeoutError, socket.timeout):
            retry = conf["retry"]
            while retry > 0:
                msg = 'Plugin: {0} timeout, start it over.'.format(self.name)
                if conf["is_debug"]:
                    dataToStdout('\r' + msg + '\n\r')
                # Share.dataToStdout('\r' + msg + '\n\r')
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
            # Share.dataToStdout('\r' + str(e) + '\n\r')
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
        except (
        requests.exceptions.InvalidURL, requests.exceptions.InvalidSchema, requests.exceptions.ContentDecodingError):
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
            errMsg += "Threads: {}".format(conf["threads"])
            if request:
                errMsg += '\n\nrequest raw:\n'
                errMsg += request.to_data().decode()
            excMsg = traceback.format_exc()
            Share.lock.acquire()
            if conf["is_debug"]:
                dataToStdout('\r' + errMsg + '\n\r')
            if createGithubIssue(errMsg, excMsg):
                dataToStdout('\r' + "[x] a issue has reported" + '\n\r')
            Share.lock.release()

        return output
