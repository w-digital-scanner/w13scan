#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/6/28 11:03 PM
# @Author  : w8ay
# @File    : plugins.py
from requests import ConnectTimeout, HTTPError, TooManyRedirects

from lib.baseproxy import Request, Response
from config import RETRY
from lib.data import Share


class PluginBase(object):

    def __init__(self):
        self.type = None
        self.target = None
        self.name = None
        self.requests: Request = None
        self.response: Response = None

    def audit(self):
        raise NotImplementedError

    def build_url(self):
        netloc = "http"
        if self.requests.https:
            netloc = "https"
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
            Share.logger.error('Plugin: {0} not defined "{1} mode'.format(self.name, 'audit'))

        except ConnectTimeout:
            retry = RETRY
            while retry > 0:
                Share.logger.debug('Plugin: {0} timeout, start it over.'.format(self.name))
                try:
                    output = self.audit()
                    break
                except ConnectTimeout:
                    Share.logger.debug('POC: {0} time-out retry failed!'.format(self.name))
                retry -= 1
            else:
                msg = "connect target '{0}' failed!".format(self.target)
                Share.logger.error(msg)

        except HTTPError as e:
            Share.logger.warning('Plugin: {0} HTTPError occurs, start it over.'.format(self.name))

        except ConnectionError as e:
            msg = "connect target '{0}' failed!".format(self.target)
            Share.logger.error(msg)

        except TooManyRedirects as e:
            Share.logger.error(str(e))

        except Exception as e:
            Share.logger.error(str(e))

        return output
