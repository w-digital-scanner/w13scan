#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/6/29 12:16 AM
# @Author  : w8ay
# @File    : filescan.py
from lib.common import get_parent_paths, get_links
from lib.plugins import PluginBase
from lib.data import Share
from lib.output import out
import requests


class W13SCAN(PluginBase):
    desc = '''基于流量动态生成敏感目录文件扫描'''
    name = "敏感文件扫描插件"

    def file(self):
        filename = ['/debug.txt', '/crossdomain.xml', '/etc/passwd', '/.bash_profile',
                    '/.rediscli_history',
                    '/.bash_history', '/.bashrc', '/.DS_Store', '/../../../../../../../../../../etc/passwd',
                    '/.bash_logout',
                    '/.vimrc', '/.htaccess', '/admin.html', '/examples/', '/.htaccess.bak',
                    '/%C0%AE%C0%AE/%C0%AE%C0%AE/%C0%AE%C0%AE/%C0%AE%C0%AE/%C0%AE%C0%AE/%C0%AE%C0%AE/%C0%AE%C0%AE/%C0%AE%C0%AE/%C0%AE%C0%AE/%C0%AE%C0%AE/etc/passwd',
                    '/db.conf', '/.history', '/composer.json',
                    '/requirements.txt', '/.htpasswd', '/composer.lock', '/web.config', '/login.php',
                    '/login.html', '/nohup.out',
                    '/htpasswd.bak', '/httpd.conf', '/.mysql_history', '/login.asp', '/database.yml',
                    '/.ssh/known_hosts',
                    '/.ssh/id_rsa', '/.ssh/id_dsa', '/id_dsa',
                    '/id_rsa',
                    '/.ssh/id_rsa.pub', '/.ssh/id_dsa.pub', '/id_rsa.pub', '/.ssh/authorized_keys', '/readme.md',
                    '/readme',
                    '/readme.txt', '/README.md', '/README', '/README.txt', '/LICENSE.txt', '/LICENSE.md', '/LICENSE',
                    '/CHANGELOG.md', '/CHANGELOG.txt', '/CHANGELOG', '/changelog.md', '/changelog.txt', '/changelog',
                    '/CONTRIBUTING.md', '/CONTRIBUTING.txt', '/CONTRIBUTING', '/install.md', '/install.txt', '/install',
                    '/INSTALL.md', '/INSTALL.txt', '/INSTALL', '/readme.html', '/data.txt',
                    '/install.sh', '/deploy.sh', '/upload.sh', '/setup.sh', '/backup.sh', '/rsync.sh', '/sync.sh',
                    '/test.sh',
                    '/run.sh', '/config.php', '/config.inc',
                    '/settings.ini',
                    '/application.ini', '/conf.ini', '/app.ini',
                    '/config.ini',
                    '/php.ini',
                    '/config.json', '/.user.ini', '/db.ini', '/.idea/workspace.xml', '/.idea/modules.xml', '/a.out',
                    '/key',
                    '/keys', '/key.txt', '/secret_key', '/secret', '/.env', '/.secret', '/.key', '/.secret_key',
                    '/temp.txt',
                    '/tmp.txt', '/sftp-config.json']
        return filename

    def audit(self):
        method = self.requests.command  # 请求方式 GET or POST
        headers = self.requests.get_headers()  # 请求头 dict类型
        url = self.build_url()  # 请求完整URL
        data = self.requests.get_body_data().decode()  # POST 数据

        resp_data = self.response.get_body_data()  # 返回数据 byte类型
        resp_str = self.response.get_body_str()  # 返回数据 str类型 自动解码
        resp_headers = self.response.get_headers()  # 返回头 dict类型

        path1 = get_parent_paths(url)
        urls = set(path1)
        for link in get_links(resp_str, url, True):
            path1 = get_parent_paths(link)
            urls |= set(path1)

        for p in urls:
            filename = self.file()
            for f in filename:
                _ = p.rstrip('/') + f
                if not Share.in_url(_):
                    Share.add_url(_)
                    try:
                        r = requests.get(_, headers=headers)
                        # out.log(_)
                        if r.status_code == 200:
                            # print(self.name)
                            out.success(_, self.name)
                    except Exception as e:
                        pass
