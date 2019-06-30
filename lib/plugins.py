#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/6/28 11:03 PM
# @Author  : w8ay
# @File    : plugins.py
from requests import ConnectTimeout, HTTPError, TooManyRedirects

from config import RETRY
from lib.baseproxy import Request, Response
from lib.data import Share


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

        except ConnectTimeout:
            retry = RETRY
            while retry > 0:
                msg = 'Plugin: {0} timeout, start it over.'.format(self.name)
                Share.dataToStdout('\r' + msg + '\n\r')
                try:
                    output = self.audit()
                    break
                except ConnectTimeout:
                    msg = 'POC: {0} time-out retry failed!'.format(self.name)
                    Share.dataToStdout('\r' + msg + '\n\r')
                retry -= 1
            else:
                msg = "connect target '{0}' failed!".format(self.target)
                Share.dataToStdout('\r' + msg + '\n\r')

        except HTTPError as e:
            msg = 'Plugin: {0} HTTPError occurs, start it over.'.format(self.name)
            Share.dataToStdout('\r' + msg + '\n\r')

        except ConnectionError as e:
            msg = "connect target '{0}' failed!".format(self.target)
            Share.dataToStdout('\r' + msg + '\n\r')

        except TooManyRedirects as e:
            if e:
                Share.dataToStdout('\r' + str(e) + '\n\r')

        except Exception as e:
            if e:
                Share.dataToStdout('\r' + str(e) + '\n\r')

        return output
