#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/9/15 9:46 PM
# @Author  : w8ay
# @File    : sensitive_info.py
import re


def sensitive_bankcard(source):
    _ = r'\D(6\d{14,18})\D'
    texts = re.findall(_, source, re.M | re.I)
    out = []
    if texts:
        for i in set(texts):
            out.append({
                "type": "bankcard",
                "content": i
            })
    return out


def sensitive_idcard(source):
    _ = r'\D([123456789]\d{5}((19)|(20))\d{2}((0[123456789])|(1[012]))((0[123456789])|([12][0-9])|(3[01]))\d{3}[Xx0-9])\D'
    texts = re.findall(_, source, re.M | re.I)
    out = []
    if texts:
        for i in set(texts):
            if len(i[0]) < 18:
                continue
            out.append({
                "type": "idycard",
                "content": i[0]
            })
    return out


def sensitive_phone(source):
    _ = r'\D(1[3578]\d{9})\D'
    texts = re.findall(_, source, re.M | re.I)
    out = []
    if texts:
        for i in set(texts):
            out.append({
                "type": "phone",
                "content": i
            })
    return out


def sensitive_email(source):
    _ = r'(([a-zA-Z0-9]+[_|\-|\.]?)*[a-zA-Z0-9]+\@([a-zA-Z0-9]+[_|\-|\.]?)*[a-zA-Z0-9]+(\.[a-zA-Z]{2,3})+)'
    texts = re.findall(_, source, re.M | re.I)
    out = []
    if texts:
        for i in set(texts):
            out.append({
                "type": "email",
                "content": i[0]
            })
    return out
