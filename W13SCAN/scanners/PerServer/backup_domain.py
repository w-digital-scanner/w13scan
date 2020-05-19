#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/21 4:45 PM
# @Author  : w8ay
# @File    : backup_domain.py
from urllib.parse import urlparse

import requests
from tld import parse_tld

from lib.core.common import generateResponse
from lib.core.enums import VulType, PLACE
from lib.core.plugins import PluginBase


class W13SCAN(PluginBase):
    name = '基于域名的备份文件'
    desc = '''扫描基于域名的备份文件'''

    def _check(self, content):
        """
            根据给定的url，探测远程服务器上是存在该文件
            文件头识别
           * rar:526172211a0700cf9073
           * zip:504b0304140000000800
           * gz：1f8b080000000000000b，也包括'.sql.gz'，取'1f8b0800' 作为keyword
           * tar.gz: 1f8b0800
           * mysqldump:                   -- MySQL dump:               2d2d204d7953514c
           * phpMyAdmin:                  -- phpMyAdmin SQL Dump:      2d2d207068704d794164
           * navicat:                     /* Navicat :                 2f2a0a204e617669636174
           * Adminer:                     -- Adminer x.x.x MySQL dump: 2d2d2041646d696e6572
           * Navicat MySQL Data Transfer: /* Navicat:                  2f2a0a4e617669636174
           * 一种未知导出方式:               -- -------:                  2d2d202d2d2d2d2d2d2d
            :param target_url:
            :return:
        """
        features = [b'\x50\x4b\x03\x04', b'\x52\x61\x72\x21',
                    b'\x2d\x2d\x20\x4d', b'\x2d\x2d\x20\x70\x68', b'\x2f\x2a\x0a\x20\x4e',
                    b'\x2d\x2d\x20\x41\x64', b'\x2d\x2d\x20\x2d\x2d', b'\x2f\x2a\x0a\x4e\x61']
        for i in features:
            if content.startswith(i):
                return True
        return False

    def audit(self):
        headers = self.requests.headers
        url = self.requests.url
        p = urlparse(url)
        domain = "{}://{}/".format(p.scheme, p.netloc)

        try:
            payloads = parse_tld(domain, fix_protocol=True, fail_silently=True)
        except AttributeError:
            payloads = None
        if not payloads:
            return

        for payload in payloads:

            for i in ['.rar', '.zip']:
                test_url = domain + payload + i
                r = requests.get(test_url, headers=headers, allow_redirects=False, stream=True)
                try:
                    content = r.raw.read(10)
                except:
                    continue

                if r.status_code == 200 and self._check(content):
                    if int(r.headers.get('Content-Length', 0)) == 0:
                        continue

                    rarsize = int(r.headers.get('Content-Length')) // 1024 // 1024
                    result = self.new_result()
                    result.init_info(self.requests.url, "备份文件下载", VulType.BRUTE_FORCE)
                    result.add_detail("payload请求", r.reqinfo, content.decode(errors='ignore'),
                                      "备份文件大小:{}M".format(rarsize), "", "", PLACE.GET)
                    self.success(result)
