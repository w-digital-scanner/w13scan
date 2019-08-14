#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/21 1:47 PM
# @Author  : w8ay
# @File    : common_set.py
import requests

from W13SCAN.lib.const import Level
from W13SCAN.lib.output import out
from W13SCAN.lib.plugins import PluginBase


class W13SCAN(PluginBase):
    desc = '''收集自BBScan的插件'''
    name = "通用敏感文件扫描插件"
    level = Level.LOW

    def generate(self):
        payloads = [{'path': '/core', 'tag': 'ELF', 'content-type': '', 'content-type_no': ''},
                    {'path': '/crossdomain.xml', 'tag': '<allow-access-from domain="*"', 'content-type': 'xml',
                     'content-type_no': ''},
                    {'path': '/debug.txt', 'tag': '', 'content-type': 'text/plain', 'content-type_no': ''},
                    {'path': '/.htaccess', 'tag': '', 'content-type': 'application/octet-stream',
                     'content-type_no': ''},
                    {'path': '/htaccess.bak', 'tag': '', 'content-type': 'application/octet-stream',
                     'content-type_no': ''},
                    {'path': '/.htpasswd', 'tag': '', 'content-type': 'application/octet-stream',
                     'content-type_no': ''},
                    {'path': '/.htpasswd.bak', 'tag': '', 'content-type': 'application/octet-stream',
                     'content-type_no': ''},
                    {'path': '/htpasswd.bak', 'tag': '', 'content-type': 'application/octet-stream',
                     'content-type_no': ''},
                    {'path': '/.mysql_history', 'tag': '', 'content-type': 'application/octet-stream',
                     'content-type_no': ''},
                    {'path': '/httpd.conf', 'tag': '', 'content-type': '', 'content-type_no': 'html'},
                    {'path': '/web.config', 'tag': '', 'content-type': 'application/octet-stream',
                     'content-type_no': ''},
                    {'path': '/server-status', 'tag': '<title>Apache Status</title>', 'content-type': '',
                     'content-type_no': ''},
                    {'path': '/solr/', 'tag': '<title>Solr Admin</title>', 'content-type': 'html',
                     'content-type_no': ''},
                    {'path': '/examples/', 'tag': '<TITLE>Apache Tomcat Examples</TITLE>', 'content-type': 'html',
                     'content-type_no': ''},
                    {'path': '/examples/servlets/servlet/SessionExample', 'tag': '<title>Sessions Example</title>',
                     'content-type': 'html', 'content-type_no': ''},
                    {'path': '/config/database.yml', 'tag': 'password', 'content-type': '', 'content-type_no': 'html'},
                    {'path': '/database.yml', 'tag': '', 'content-type': '', 'content-type_no': 'html'},
                    {'path': '/db.conf', 'tag': '', 'content-type': '', 'content-type_no': 'html'},
                    {'path': '/db.ini', 'tag': '[', 'content-type': '', 'content-type_no': 'html'},
                    {'path': '/jmx-console/HtmlAdaptor', 'tag': 'JBoss Management Console', 'content-type': '',
                     'content-type_no': ''},
                    {'path': '/cacti/', 'tag': '<title>Login to Cacti</title>', 'content-type': '',
                     'content-type_no': ''},
                    {'path': '/zabbix/', 'tag': '<title>Zabbix</title>', 'content-type': '', 'content-type_no': ''},
                    {'path': '/jenkins/static/f3a41d2f/css/style.css', 'tag': 'jenkins-home-link',
                     'content-type': 'text/css', 'content-type_no': ''},
                    {'path': '/static/f3a41d2f/css/style.css', 'tag': 'jenkins-home-link', 'content-type': 'text/css',
                     'content-type_no': ''},
                    {'path': '/script', 'tag': 'Type in an arbitrary', 'content-type': '', 'content-type_no': ''},
                    {'path': '/jenkins/script', 'tag': 'Type in an arbitrary', 'content-type': '',
                     'content-type_no': ''},
                    {'path': '/exit', 'tag': '<title>POST required</title>', 'content-type': '', 'content-type_no': ''},
                    {'path': '/memadmin/index.php', 'tag': '<title>Login - MemAdmin', 'content-type': '',
                     'content-type_no': ''},
                    {'path': '/phpmyadmin/index.php', 'tag': '<title>phpMyAdmin', 'content-type': '',
                     'content-type_no': ''},
                    {'path': '/phpMyAdmin/index.php', 'tag': '<title>phpMyAdmin', 'content-type': '',
                     'content-type_no': ''},
                    {'path': '/_phpmyadmin/index.php', 'tag': '<title>phpMyAdmin', 'content-type': '',
                     'content-type_no': ''},
                    {'path': '/pma/index.php', 'tag': '<title>phpMyAdmin', 'content-type': '', 'content-type_no': ''},
                    {'path': '/ganglia/', 'tag': '<title>Ganglia', 'content-type': '', 'content-type_no': ''},
                    {'path': '/resin-doc/resource/tutorial/jndi-appconfig/test?inputFile=/etc/profile',
                     'tag': '/etc/profile.d/*.sh', 'content-type': '', 'content-type_no': ''},
                    {'path': '/resin-doc/viewfile/?contextpath=/&servletpath=&file=index.jsp',
                     'tag': 'This is the default start page for the Resin server', 'content-type': '',
                     'content-type_no': ''},
                    {'path': '/resin-admin/', 'tag': '<title>Resin Admin Login for', 'content-type': '',
                     'content-type_no': ''},
                    {'path': '/data.txt', 'tag': '', 'content-type': 'text/plain', 'content-type_no': ''},
                    {'path': '/install.txt', 'tag': '', 'content-type': 'text/plain', 'content-type_no': ''},
                    {'path': '/INSTALL.TXT', 'tag': '', 'content-type': 'text/plain', 'content-type_no': ''},
                    {'path': '/upload.do', 'tag': 'type="file"', 'content-type': 'html', 'content-type_no': ''},
                    {'path': '/upload.jsp', 'tag': 'type="file"', 'content-type': 'html', 'content-type_no': ''},
                    {'path': '/upload.php', 'tag': 'type="file"', 'content-type': 'html', 'content-type_no': ''},
                    {'path': '/upfile.php', 'tag': 'type="file"', 'content-type': 'html', 'content-type_no': ''},
                    {'path': '/upload.html', 'tag': 'type="file"', 'content-type': 'html', 'content-type_no': ''}]
        if self.response.system is None or self.response.system == "*NIX":
            temp = [
                {'path': '/.bash_history', 'tag': '', 'content-type': 'application/octet-stream',
                 'content-type_no': ''},
                {'path': '/.rediscli_history', 'tag': '', 'content-type': 'application/octet-stream',
                 'content-type_no': ''},
                {'path': '/.bashrc', 'tag': '', 'content-type': 'application/octet-stream', 'content-type_no': ''},
                {'path': '/.bash_profile', 'tag': '', 'content-type': 'application/octet-stream',
                 'content-type_no': ''},
                {'path': '/.bash_logout', 'tag': '', 'content-type': 'application/octet-stream',
                 'content-type_no': ''},
                {'path': '/.vimrc', 'tag': '', 'content-type': 'application/octet-stream', 'content-type_no': ''},
                {'path': '/.DS_Store', 'tag': '', 'content-type': 'application/octet-stream',
                 'content-type_no': ''},
                {'path': '/.history', 'tag': '', 'content-type': 'application/octet-stream', 'content-type_no': ''},
                {'path': '/nohup.out', 'tag': '', 'content-type': 'application/octet-stream',
                 'content-type_no': ''},
                {'path': '/.ssh/known_hosts', 'tag': '', 'content-type': 'application/octet-stream',
                 'content-type_no': ''},
                {'path': '/.ssh/id_rsa', 'tag': 'PRIVATE KEY-', 'content-type': '', 'content-type_no': ''},
                {'path': '/id_rsa', 'tag': 'PRIVATE KEY-', 'content-type': '', 'content-type_no': ''},
                {'path': '/.ssh/id_rsa.pub', 'tag': 'ssh-rsa', 'content-type': '', 'content-type_no': ''},
                {'path': '/.ssh/id_dsa', 'tag': 'PRIVATE KEY-', 'content-type': '', 'content-type_no': ''},
                {'path': '/id_dsa', 'tag': 'PRIVATE KEY-', 'content-type': '', 'content-type_no': ''},
                {'path': '/.ssh/id_dsa.pub', 'tag': 'ssh-dss', 'content-type': '', 'content-type_no': ''},
                {'path': '/.ssh/authorized_keys', 'tag': 'ssh-rsa', 'content-type': '', 'content-type_no': ''},
            ]
            payloads.extend(temp)
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

        payloads = self.generate()
        for payload in payloads:
            test_url = domain.rstrip('/') + payload["path"]
            r = requests.get(test_url, headers=headers, allow_redirects=False)
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
            out.success(test_url, self.name, length="{}".format(len(r.content)))
