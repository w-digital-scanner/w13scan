#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2020/4/6 1:24 PM
# @Author  : w8ay
# @File    : reverse_api.py
import time

from config import USE_REVERSE, REVERSE_DNS, REVERSE_HTTP_PORT, REVERSE_HTTP_IP, REVERSE_RMI_IP, REVERSE_RMI_PORT, \
    REVERSE_SLEEP
from lib.core.common import random_str
import requests


class reverseApi(object):

    def __init__(self):
        self.web_api = "http://{}:{}/".format(REVERSE_HTTP_IP, REVERSE_HTTP_PORT)
        self.rmi_api = "{}:{}".format(REVERSE_RMI_IP, REVERSE_RMI_PORT)
        self.dns_api = REVERSE_DNS
        self.sleep = REVERSE_SLEEP
        self.use = USE_REVERSE

    def isUseReverse(self):
        return self.use

    def generate_dns_token(self) -> dict:
        token = random_str(5)
        obj = {
            "token": token,
            "fullname": "{}.{}".format(token, self.dns_api)
        }
        return obj

    def generate_http_token(self) -> dict:
        token = random_str(5)
        obj = {
            "token": token,
            "fullname": self.web_api + token
        }
        return obj

    def generate_rmi_token(self) -> dict:
        token = random_str(5)
        obj = {
            "token": token,
            "fullname": self.rmi_api
        }
        return obj

    def check(self, token) -> list:
        time.sleep(self.sleep)
        api = self.web_api + "_/search?q=" + token
        resp = requests.get(api).json()
        return resp

    def show_all(self) -> list:
        '''
        显示回显平台所有记录
        :return:
        '''
        api = self.web_api + "_/search?q=" + "all"
        resp = requests.get(api).json()
        return resp
