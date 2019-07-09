#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/6/29 12:16 AM
# @Author  : w8ay
# @File    : filescan.py
import requests

from lib.output import out
from lib.plugins import PluginBase


class W13SCAN(PluginBase):
    desc = '''基于流量动态生成敏感目录文件扫描'''
    name = "敏感文件扫描插件"

    def file(self):
        filename = ['/debug.txt', '/crossdomain.xml', '/etc/passwd', '/.bash_profile',
                    '/.rediscli_history',
                    '/.bash_history', '/.bashrc', '/.DS_Store',
                    '/.bash_logout',
                    '/.vimrc', '/examples/', '/.htaccess.bak',
                    '/db.conf', '/.history', '/composer.json',
                    '/requirements.txt', '/.htpasswd', '/composer.lock', '/web.config', '/login.php',
                    '/nohup.out',
                    '/htpasswd.bak', '/httpd.conf', '/.mysql_history', '/login.asp', '/database.yml',
                    '/.ssh/known_hosts',
                    '/.ssh/id_rsa', '/.ssh/id_dsa', '/id_dsa',
                    '/id_rsa',
                    '/.ssh/id_rsa.pub', '/.ssh/id_dsa.pub', '/id_rsa.pub', '/.ssh/authorized_keys', '/readme.md',
                    '/readme',
                    '/readme.txt', '/README.md', '/README', '/README.txt', '/LICENSE.txt', '/LICENSE.md', '/LICENSE',
                    '/CHANGELOG.md', '/CHANGELOG.txt', '/CHANGELOG', '/changelog.md', '/changelog.txt', '/changelog',
                    '/CONTRIBUTING.md', '/CONTRIBUTING.txt', '/CONTRIBUTING', '/install.md', '/install.txt', '/install',
                    '/INSTALL.md', '/INSTALL.txt', '/INSTALL', '/data.txt',
                    '/install.sh', '/deploy.sh', '/upload.sh', '/setup.sh', '/backup.sh', '/rsync.sh', '/sync.sh',
                    '/test.sh',
                    '/run.sh', '/config.php', '/config.inc',
                    '/settings.ini',
                    '/application.ini', '/conf.ini', '/app.ini',
                    '/config.ini',
                    '/php.ini',
                    '/config.json', '/.user.ini', '/db.ini', '/a.out',
                    '/key',
                    '/keys', '/key.txt', '/secret_key', '/secret', '/.env', '/.secret', '/.key', '/.secret_key',
                    '/temp.txt',
                    '/tmp.txt', '更新日志.txt']
        return filename

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

        filename = self.file()
        success = []
        for f in filename:
            _ = url.rstrip('/') + f
            try:
                r = requests.get(_, headers=headers, allow_redirects=False)
                # out.log(_)
                if r.status_code != 404:
                    success.append({"url": _, "code": len(r.text)})
                    # print(self.name)
            except Exception as e:
                pass
        if len(success) < 5:
            for i in success:
                out.success(i["url"], self.name)
        else:
            result = {}
            for item in success:
                length = item.get("len", 0)
                if length not in result:
                    result[length] = list()
                result[length].append(item["url"])

            for k, v in result.items():
                if len(v) > 3:
                    continue

                for i in v:
                    out.success(i, self.name)
