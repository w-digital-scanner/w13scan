#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/6/29 12:16 AM
# @Author  : w8ay
# @File    : filescan.py
from lib.common import get_parent_paths
from lib.plugins import PluginBase
from lib.data import Share
from lib.output import out
import requests


class W13SCAN(PluginBase):
    desc = '''基于流量动态生成敏感目录文件扫描'''

    def file(self):
        filename = ['/core', '/debug.txt', '/debug', '/crossdomain.xml', '/etc/passwd', '/.bash_profile',
                    '/.rediscli_history',
                    '/.bash_history', '/.bashrc', '/.DS_Store', '/../../../../../../../../../../etc/passwd',
                    '/.bash_logout',
                    '/.vimrc', '/.htaccess', '/admin.html', '/examples/', '/.htaccess.bak',
                    '/%C0%AE%C0%AE/%C0%AE%C0%AE/%C0%AE%C0%AE/%C0%AE%C0%AE/%C0%AE%C0%AE/%C0%AE%C0%AE/%C0%AE%C0%AE/%C0%AE%C0%AE/%C0%AE%C0%AE/%C0%AE%C0%AE/etc/passwd',
                    '/db.conf', '/examples/servlets/servlet/SessionExample', '/manager/html', '/.history', '/admin.php',
                    '/admin.jsp', '/admin', '/login', '/composer.json', '/server-status', '/signin', '/admin.do',
                    '/requirements.txt', '/solr/', '/.htpasswd', '/composer.lock', '/web.config', '/login.php',
                    '/login.html', '/config/database.yml', '/nohup.out', '/login.jsp', '/.htpasswd.bak', '/login.do',
                    '/admin.asp',
                    '/htpasswd.bak', '/httpd.conf', '/.mysql_history', '/login.asp', '/database.yml',
                    '/jmx-console/HtmlAdaptor',
                    '/cacti/', '/zabbix/', '/jenkins/script', '/memadmin/index.php', '/phpmyadmin/index.php',
                    '/phpMyAdmin/index.php', '/ganglia/', '/_phpmyadmin/index.php', '/pma/index.php',
                    '/resin-doc/resource/tutorial/jndi-appconfig/test%3FinputFile=/etc/profile', '/resin-admin/',
                    '/resin-doc/viewfile/%3Fcontextpath=/&servletpath=&file=index.jsp', '/.ssh/known_hosts',
                    '/.ssh/id_rsa', '/.ssh/id_dsa', '/id_dsa',
                    '/id_rsa',
                    '/.ssh/id_rsa.pub', '/.ssh/id_dsa.pub', '/id_rsa.pub', '/.ssh/authorized_keys', '/readme.md',
                    '/readme',
                    '/readme.txt', '/README.md', '/README', '/README.txt', '/LICENSE.txt', '/LICENSE.md', '/LICENSE',
                    '/CHANGELOG.md', '/CHANGELOG.txt', '/CHANGELOG', '/changelog.md', '/changelog.txt', '/changelog',
                    '/CONTRIBUTING.md', '/CONTRIBUTING.txt', '/CONTRIBUTING', '/install.md', '/install.txt', '/install',
                    '/INSTALL.md', '/INSTALL.txt', '/INSTALL', '/readme.html', '/data.txt', '/vendor/composer/LICENSE',
                    '/install.sh', '/deploy.sh', '/upload.sh', '/setup.sh', '/backup.sh', '/rsync.sh', '/sync.sh',
                    '/test.sh',
                    '/run.sh', '/config.php', '/config.inc', '/config/config.php', '/config/config.inc',
                    '/settings.ini',
                    '/application.ini', '/conf.ini', '/app.ini', '/configuration.ini', '/configs/application.ini',
                    '/config.ini',
                    '/config/config.ini', '/conf/config.ini', '/favicon.ico', '/application/configs/application.ini',
                    '/php.ini',
                    '/config.json', '/.user.ini', '/db.ini', '/.idea/workspace.xml', '/.idea/modules.xml', '/a.out',
                    '/key',
                    '/keys', '/key.txt', '/secret_key', '/secret', '/.env', '/.secret', '/.key', '/.secret_key',
                    '/temp.txt',
                    '/tmp.txt', '/sftp-config.json', '/index.php~', '/config.php~', '/index.php.bak', '/config.php.bak',
                    '/db.php.bak', '/config.inc.php.bak', '/.config.inc.php.swp', '/.index.php.swp',
                    '/config/.config.php.swp',
                    '/.config.php.swp', '/.settings.php.swp', '/.database.php.swp', '/.db.php.swp', '/.mysql.php.swp',
                    '/index.cgi.bak', '/app.cfg', '/upload.php', '/upload.jsp', '/upload.asp', '/upload.aspx',
                    '/upload.html',
                    '/upload.do', '/upfile.php', '/upfile.asp', '/upfile.jsp', '/upfile.aspx', '/upfile.html',
                    '/upfile.do',
                    '/phpinfo.php', '/info.php', '/i.php', '/tz.php', '/php.php', '/test.php', '/1.php', '/x.php',
                    '/p.php',
                    '/debug.php', '/db.inc', '/db.sqlite', '/db.sqlite3', '/database.sql', '/data.sql', '/test.sql',
                    '/db.sql',
                    '/backup.sql', '/admin.sql', '/dump.sql', '/index.bak', '/server.cfg', '/proxy.pac', '/code.tar.gz',
                    '/src.tar.gz', '/htdocs.tar.gz', '/webserver.tar.gz', '/tools.tar.gz', '/site.tar.gz',
                    '/webroot.zip',
                    '/install.tar.gz', '/build.tar.gz', '/deploy.tar.gz', '/config.tar.gz', '/conf.tar.gz',
                    '/conf/conf.zip',
                    '/o.tar.gz', '/x.tar.gz', '/output.tar.gz', '/backup.sql.gz', '/database.sql.gz', '/dump.sql.gz',
                    '/db.sql.gz',
                    '/back.tar.bz2', '/a.zip', '/a.tar.gz', '/a.rar', '/a.7z', '/a.gz', '/a.tgz', '/a.tar.bz2',
                    '/1.zip',
                    '/1.tar.gz', '/1.rar', '/1.7z', '/1.gz', '/1.tgz', '/1.tar.bz2', '/old.zip', '/old.tar.gz',
                    '/old.rar',
                    '/old.7z', '/old.gz', '/old.tar.bz2', '/old.tgz', '/index.tar.gz', '/index.zip', '/index.rar',
                    '/index.gz',
                    '/index.7z', '/index.tgz', '/index.tar.bz2', '/sql.zip', '/sql.tar.gz', '/sql.rar', '/sql.7z',
                    '/sql.gz',
                    '/sql.tgz', '/sql.tar.bz2', '/package.zip', '/package.tar.gz', '/package.rar', '/package.7z',
                    '/package.gz',
                    '/package.tgz', '/package.tar.bz2', '/website.zip', '/website.tar.gz', '/website.rar',
                    '/website.7z',
                    '/website.gz', '/website.tgz', '/website.tar.bz2', '/upload.tar.gz', '/upload.zip', '/upload.rar',
                    '/upload.7z', '/upload.gz', '/upload.tgz', '/upload.tar.bz2', '/admin.zip', '/admin.tar.gz',
                    '/admin.rar',
                    '/admin.7z', '/admin.gz', '/admin.tgz', '/admin.tar.bz2', '/wwwroot.zip', '/wwwroot.tar.gz',
                    '/wwwroot.rar',
                    '/wwwroot.7z', '/wwwroot.gz', '/wwwroot.tgz', '/wwwroot.tar.bz2', '/www.zip', '/www.tar.gz',
                    '/www.rar',
                    '/www.7z', '/www.tar.bz2', '/www.gz', '/www.tgz', '/web.tar.gz', '/web.zip', '/web.rar', '/web.7z',
                    '/web.gz',
                    '/web.tgz', '/web.tar.bz2', '/ftp.zip', '/ftp.tar.gz', '/ftp.rar', '/ftp.7z', '/ftp.gz', '/ftp.tgz',
                    '/ftp.tar.bz2', '/database.zip', '/database.tar.gz', '/database.rar', '/database.7z',
                    '/database.gz',
                    '/database.tgz', '/database.tar.bz2', '/data.zip', '/data.rar', '/data.tar.gz', '/data.7z',
                    '/data.gz',
                    '/data.tgz', '/data.tar.bz2', '/db.zip', '/db.tar.gz', '/db.rar', '/db.7z', '/db.gz', '/db.tgz',
                    '/db.tar.bz2',
                    '/backup.zip', '/backup.tar.gz', '/backup.rar', '/backup.7z', '/backup.gz', '/backup.tgz',
                    '/backup.tar.bz2',
                    '/test.tar.gz', '/test.zip', '/test.rar', '/test.7z', '/test.gz', '/test.tgz', '/test.tar.bz2',
                    '/tmp.zip',
                    '/tmp.tar.gz', '/tmp.rar', '/tmp.gz', '/tmp.7z', '/tmp.tar.bz2', '/tmp.tgz', '/temp.zip',
                    '/temp.rar',
                    '/temp.tar.gz', '/temp.7z', '/temp.tar.bz2', '/temp.tgz', '/temp.gz', '/shell.php', '/shell.jsp',
                    '/shell.jspx', '/shell.asp', '/shell.aspx', '/webshell.jsp', '/webshell.php', '/webshell.jspx',
                    '/webshell.asp', '/webshell.aspx', '/1.php', '/1.jsp', '/1.asp', '/1.jspx', '/1.aspx', '/s.jsp',
                    '/s.jspx',
                    '/s.php', '/s.asp', '/s.aspx', '/x.php', '/x.jsp', '/x.jspx', '/x.asp', '/x.aspx', '/ooxx.jsp',
                    '/ooxx.jspx',
                    '/ooxx.php', '/ooxx.asp', '/ooxx.aspx', '/dama.php', '/dama.jsp', '/dama.jspx', '/dama.asp',
                    '/dama.aspx',
                    '/test.jsp', '/test.php', '/test.jspx', '/test.asp', '/test.aspx', '/phpspy.php', '/jspspy.jsp',
                    '/jspspy.jspx', '/aspxspy.aspx', '/WEB-INF/web.xml']
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
        for p in path1:
            filename = self.file()
            for f in filename:
                _ = p.rstrip('/') + f
                if not Share.in_url(_):
                    Share.add_url(_)
                    try:
                        r = requests.get(_, headers=headers)
                        # out.log(_)
                        if r.status_code == 200:
                            out.success("Success:" + _)
                    except Exception as e:
                        pass
