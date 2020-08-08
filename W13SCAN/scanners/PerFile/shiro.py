#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2020/8/6 6:19 PM
# @Author  : w8ay
# @File    : shrio_check.py
import base64

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from api import PluginBase, WEB_PLATFORM, conf, ResultObject, VulType, generateResponse
from lib.core.common import paramToDict, url_dict2str
from lib.core.enums import PLACE, HTTPMETHOD


class W13SCAN(PluginBase):
    name = 'Shiro框架检测以及Key爆破'
    desc = '''检测以及依赖shiro自身类检测爆破key'''

    def generator_payload(self, key):
        payload = b'\xac\xed\x00\x05sr\x002org.apache.shiro.subject.SimplePrincipalCollection\xa8\x7fX%\xc6\xa3\x08J\x03\x00\x01L\x00\x0frealmPrincipalst\x00\x0fLjava/util/Map;xppw\x01\x00x'
        iv = b'w\xcf\xd7\x98\xa8\xe9LD\x97LN\xd0\xa6\n\xb8\x1a'
        backend = default_backend()
        cipher = Cipher(algorithms.AES(base64.b64decode(key)), modes.CBC(iv), backend=backend)
        encryptor = cipher.encryptor()
        BS = algorithms.AES.block_size
        pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
        file_body = pad(payload)
        ct = encryptor.update(file_body)
        base64_ciphertext = base64.b64encode(iv + ct)
        return base64_ciphertext.decode()

    def _check_key(self):
        keys = [
            'kPH+bIxk5D2deZiIxcaaaA==', '4AvVhmFLUs0KTA3Kprsdag==', 'WkhBTkdYSUFPSEVJX0NBVA==',
            'RVZBTk5JR0hUTFlfV0FPVQ==', 'U3ByaW5nQmxhZGUAAAAAAA==',
            'cGljYXMAAAAAAAAAAAAAAA==', 'd2ViUmVtZW1iZXJNZUtleQ==', 'fsHspZw/92PrS3XrPW+vxw==',
            'sHdIjUN6tzhl8xZMG3ULCQ==', 'WuB+y2gcHRnY2Lg9+Aqmqg==',
            'ertVhmFLUs0KTA3Kprsdag==', '2itfW92XazYRi5ltW0M2yA==', '6ZmI6I2j3Y+R1aSn5BOlAA==',
            'f/SY5TIve5WWzT4aQlABJA==', 'Jt3C93kMR9D5e8QzwfsiMw==',
            'aU1pcmFjbGVpTWlyYWNsZQ==',
        ]
        for key in keys:
            payload = self.generator_payload(key)
            reqHeader = self.requests.headers
            if "Cookie" not in reqHeader:
                reqHeader["Cookie"] = ""
            _cookie = paramToDict(reqHeader["Cookie"], place=PLACE.COOKIE)
            _cookie["rememberMe"] = payload
            reqHeader["Cookie"] = url_dict2str(_cookie, PLACE.COOKIE)
            req = None
            if self.requests.method == HTTPMETHOD.GET:
                req = requests.get(self.requests.url, headers=reqHeader)
            elif self.requests.method == HTTPMETHOD.POST:
                req = requests.post(self.requests.url, data=self.requests.post_data, headers=reqHeader)
            if req and "deleteMe" not in req.headers.get('Set-Cookie', ''):
                result = ResultObject(self)
                result.init_info(self.requests.url, "Shiro Key发现", VulType.CMD_INNJECTION)
                result.add_detail("payload探测", req.reqinfo, generateResponse(req),
                                  "Cookie中rememberMe可以被反序列化", "rememberMe", payload, PLACE.COOKIE)
                self.success(result)
                return True
        return False

    def audit(self):
        respHeader = self.response.headers
        isShiro = False
        if "deleteMe" in respHeader.get('Set-Cookie', ''):
            isShiro = True
            result = ResultObject(self)
            result.init_info(self.requests.url, "Shiro框架发现", VulType.BASELINE)
            result.add_detail("payload探测", self.requests.raw, self.response.raw,
                              "在返回的cookie中发现了deleteMe标记", "", "", PLACE.GET)
            self.success(result)
        if WEB_PLATFORM.JAVA not in self.response.programing and conf.level < 2 and not isShiro:
            return
        if not isShiro:
            # 如果不是shiro框架，检测一下
            reqHeader = self.requests.headers
            if "Cookie" not in reqHeader:
                reqHeader["Cookie"] = ""
            _cookie = paramToDict(reqHeader["Cookie"], place=PLACE.COOKIE)
            _cookie["rememberMe"] = "2"
            reqHeader["Cookie"] = url_dict2str(_cookie, PLACE.COOKIE)
            req = None
            if self.requests.method == HTTPMETHOD.GET:
                req = requests.get(self.requests.url, headers=reqHeader)
            elif self.requests.method == HTTPMETHOD.POST:
                req = requests.post(self.requests.url, data=self.requests.post_data, headers=reqHeader)
            if req and "deleteMe" in req.headers.get('Set-Cookie', ''):
                isShiro = True
                result = ResultObject(self)
                result.init_info(self.requests.url, "Shiro框架发现", VulType.BASELINE)
                result.add_detail("payload探测", req.reqinfo, generateResponse(req),
                                  "在cookie中加入rememberMe=1，在返回cookie发现了deleteMe标记，可尝试爆破shiro的key", "", "", PLACE.GET)
                self.success(result)

        # 爆破
        if isShiro:
            self._check_key()
