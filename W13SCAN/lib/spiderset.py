#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/5 4:00 PM
# @Author  : w8ay
# @File    : spiderset.py
import threading
import urllib
from urllib import parse as urlparse
from urllib.request import unquote

from W13SCAN.thirdpart.simhash import Simhash

Chars = [',', '-', '_']


def url_etl(url):
    '''
    url泛化处理
    :param url: 原始url
    :return: 处理过后的url
    '''
    params_new = {}
    u = urlparse.urlparse(url)
    query = unquote(u.query)
    query_new = ''
    if query:
        params = urlparse.parse_qsl(query, True)
        for k, v in params:
            if v:
                params_new[k] = etl(v)
        query_new = urllib.parse.urlencode(params_new)

    path_new = etl(u.path, True)

    url_new = urlparse.urlunparse(
        (u.scheme, u.netloc, path_new, u.params, query_new, u.fragment))
    return url_new


def etl(str, onlyNUM=False):
    '''
    传入一个字符串，将里面的字母转化为A，数字转化为N，特殊符号转换为T，其他符号或者字符转化成C
    :param str:
    :param onlyNUM:只换数字
    :return:
    '''
    chars = ""
    for c in str:
        c = c.lower()
        if not onlyNUM:
            if ord('a') <= ord(c) <= ord('z') and not onlyNUM:
                chars += 'A'
            elif ord('0') <= ord(c) <= ord('9'):
                chars += 'N'
            elif c in Chars:
                chars += 'T'
            else:
                chars += 'C'
        else:
            if ord('0') <= ord(c) <= ord('9'):
                chars += 'N'
            else:
                chars += c
    return chars


def url_compare(url, link):
    dis = Simhash(url).distance(Simhash(link))
    if -2 < dis < 5:
        return True
    else:
        return False


def reduce_urls(ori_urls):
    '''
    对url列表去重
    :param ori_urls: 原始url列表
    :return: 去重后的url列表
    '''
    etl_urls = []
    result_urls = []
    for ori_url in ori_urls:
        etl = url_etl(ori_url)
        print(etl)
        score = 0
        if etl_urls:
            for etl_url in etl_urls:
                if not url_compare(etl, etl_url):
                    score += 1

            if score == len(etl_urls):
                result_urls.append(ori_url)
                etl_urls.append(etl)
        else:
            etl_urls.append(etl)
            result_urls.append(ori_url)

    return result_urls


class SpiderSet(object):
    """
    基于Google Simhash算法
    """

    def __init__(self):
        self.spider_list = {
            "PerFile": {},
            "PerFolder": {},
            "PerScheme": {},
            "PostScan": {}
        }
        self.lock = threading.Lock()

    def add(self, url, plugin):
        """
        添加成功返回True，添加失败有重复返回False
        :param url:
        :param plugin:
        :return:bool
        """
        ret = True
        if not (isinstance(url, str) and isinstance(plugin, str)):
            url = str(url)
            plugin = str(plugin)

        self.lock.acquire()
        if plugin not in self.spider_list:
            self.spider_list[plugin] = {}
        netloc = urlparse.urlparse(url).netloc
        if netloc not in self.spider_list[plugin]:
            self.spider_list[plugin][netloc] = []
        etl = url_etl(url)  # url泛化表达式
        score = 0
        for etl_url in self.spider_list[plugin][netloc]:
            if not url_compare(etl, etl_url):
                score += 1
        if score == len(self.spider_list[plugin][netloc]):
            self.spider_list[plugin][netloc].append(etl)
        else:
            ret = False
        self.lock.release()
        return ret
