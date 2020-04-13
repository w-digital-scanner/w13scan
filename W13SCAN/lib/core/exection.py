#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2020/4/4 1:08 PM
# @Author  : w8ay
# @File    : exection.py

class BasicError(Exception):
    pass


class PluginCheckError(BasicError):

    def __init__(self, info):
        super().__init__(self)
        self.errorinfo = info

    def __str__(self):
        return self.errorinfo

