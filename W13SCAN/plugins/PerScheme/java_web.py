#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/21 3:58 PM
# @Author  : w8ay
# @File    : java_web.py
import requests

from W13SCAN.lib.const import Level
from W13SCAN.lib.output import out
from W13SCAN.lib.plugins import PluginBase


class W13SCAN(PluginBase):
    desc = '''收集自BBScan的插件'''
    name = "JAVA WEB敏感文件"
    level = Level.LOW

    def generate(self):
        payloads = [{'path': '/WEB-INF/web.xml', 'tag': '<?xml', 'content-type': 'xml', 'content-type_no': ''},
                    {'path': '/WEB-INF/web.xml.bak', 'tag': '<?xml', 'content-type': '', 'content-type_no': ''},
                    {'path': '/WEB-INF/applicationContext.xml', 'tag': '<?xml', 'content-type': 'xml',
                     'content-type_no': ''},
                    {'path': '/WEB-INF/config.xml', 'tag': '<?xml', 'content-type': 'xml', 'content-type_no': ''},
                    {'path': '/WEB-INF/spring.xml', 'tag': '<?xml', 'content-type': 'xml', 'content-type_no': ''},
                    {'path': '/WEB-INF/struts-config.xml', 'tag': '<?xml', 'content-type': 'xml',
                     'content-type_no': ''},
                    {'path': '/WEB-INF/struts-front-config.xml', 'tag': '<?xml', 'content-type': 'xml',
                     'content-type_no': ''},
                    {'path': '/WEB-INF/struts/struts-config.xml', 'tag': '<?xml', 'content-type': 'xml',
                     'content-type_no': ''},
                    {'path': '/WEB-INF/classes/spring.xml', 'tag': '<?xml', 'content-type': 'xml',
                     'content-type_no': ''},
                    {'path': '/WEB-INF/classes/struts.xml', 'tag': '<?xml', 'content-type': 'xml',
                     'content-type_no': ''},
                    {'path': '/WEB-INF/classes/struts_manager.xml', 'tag': '<?xml', 'content-type': 'xml',
                     'content-type_no': ''},
                    {'path': '/WEB-INF/classes/conf/datasource.xml', 'tag': '<?xml', 'content-type': 'xml',
                     'content-type_no': ''},
                    {'path': '/WEB-INF/classes/data.xml', 'tag': '<?xml', 'content-type': 'xml', 'content-type_no': ''},
                    {'path': '/WEB-INF/classes/config/applicationContext.xml', 'tag': '<?xml', 'content-type': 'xml',
                     'content-type_no': ''},
                    {'path': '/WEB-INF/classes/applicationContext.xml', 'tag': '<?xml', 'content-type': 'xml',
                     'content-type_no': ''},
                    {'path': '/WEB-INF/classes/conf/spring/applicationContext-datasource.xml', 'tag': '<?xml',
                     'content-type': 'xml', 'content-type_no': ''},
                    {'path': '/WEB-INF/config/db/dataSource.xml', 'tag': '<?xml', 'content-type': 'xml',
                     'content-type_no': ''},
                    {'path': '/WEB-INF/spring-cfg/applicationContext.xml', 'tag': '<?xml', 'content-type': 'xml',
                     'content-type_no': ''},
                    {'path': '/WEB-INF/dwr.xml', 'tag': '<?xml', 'content-type': 'xml', 'content-type_no': ''},
                    {'path': '/WEB-INF/classes/hibernate.cfg.xml', 'tag': '<?xml', 'content-type': 'xml',
                     'content-type_no': ''},
                    {'path': '/WEB-INF/classes/rabbitmq.xml', 'tag': '<?xml', 'content-type': 'xml',
                     'content-type_no': ''},
                    {'path': '/WEB-INF/conf/activemq.xml', 'tag': '<?xml', 'content-type': 'xml',
                     'content-type_no': ''},
                    {'path': '/server.xml', 'tag': '<?xml', 'content-type': 'xml', 'content-type_no': ''},
                    {'path': '/config/database.yml', 'tag': '', 'content-type': '', 'content-type_no': 'html'},
                    {'path': '/configprops', 'tag': 'serverProperties', 'content-type': '', 'content-type_no': ''},
                    {'path': '/WEB-INF/database.properties', 'tag': '', 'content-type': '', 'content-type_no': 'html'},
                    {'path': '/WEB-INF/web.properties', 'tag': '', 'content-type': '', 'content-type_no': 'html'},
                    {'path': '/WEB-INF/log4j.properties', 'tag': '', 'content-type': '', 'content-type_no': 'html'},
                    {'path': '/WEB-INF/classes/dataBase.properties', 'tag': '', 'content-type': '',
                     'content-type_no': 'html'},
                    {'path': '/WEB-INF/classes/application.properties', 'tag': '', 'content-type': '',
                     'content-type_no': 'html'},
                    {'path': '/WEB-INF/classes/jdbc.properties', 'tag': '', 'content-type': '',
                     'content-type_no': 'html'},
                    {'path': '/WEB-INF/classes/db.properties', 'tag': '', 'content-type': '',
                     'content-type_no': 'html'},
                    {'path': '/WEB-INF/classes/conf/jdbc.properties', 'tag': '', 'content-type': '',
                     'content-type_no': 'html'},
                    {'path': '/WEB-INF/classes/security.properties', 'tag': '', 'content-type': '',
                     'content-type_no': 'html'},
                    {'path': '/WEB-INF/conf/database_config.properties', 'tag': '', 'content-type': '',
                     'content-type_no': 'html'},
                    {'path': '/WEB-INF/config/dbconfig', 'tag': 'passw', 'content-type': '', 'content-type_no': 'html'}]
        return payloads

    def audit(self):
        method = self.requests.command  # 请求方式 GET or POST
        headers = self.requests.get_headers()  # 请求头 dict类型
        url = self.build_url()  # 请求完整URL

        resp_data = self.response.get_body_data()  # 返回数据 byte类型
        resp_str = self.response.get_body_str()  # 返回数据 str类型 自动解码
        resp_headers = self.response.get_headers()  # 返回头 dict类型

        p = self.requests.urlparse
        params = self.requests.params
        netloc = self.requests.netloc

        domain = "{}://{}/".format(p.scheme, p.netloc)
        if self.response.language is None or self.response.language == "JAVA":
            payloads = self.generate()

            for payload in payloads:
                test_url = domain.rstrip('/') + payload["path"]
                r = requests.get(test_url, headers=headers)
                if r.status_code != 200:
                    continue
                if payload["tag"]:
                    if payload["tag"] not in r.text:
                        continue
                if payload["content-type"]:
                    if payload['content-type'] not in r.headers.get('Content-Type', ''):
                        continue
                if payload["content-type_no"]:
                    if payload["content-type_no"] in r.headers.get('Content-Type', ''):
                        continue
                out.success(test_url, self.name)
