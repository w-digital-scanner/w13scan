#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/11 4:32 PM
# @Author  : w8ay
# @File    : phpinfo_helper.py

import re


def get_phpinfo(html) -> list:
    phpinfo_dict = [
        ('<td class="e">allow_url_fopen<\/td><td class="v">On<\/td>', 'allow_url_fopen: On (允许使用fopen函数打开网页)'),
        ('<td class="e">asp_tags<\/td><td class="v">On<\/td>', 'asp_tags: On (可使用asp的标签解析)'),
        ('<td class="e">register_globals<\/td><td class="v">On<\/td>', 'register_globals: On'),
        ('<td class="e">enable_dl<\/td><td class="v">On<\/td>',
         'enable_dl: On (可利用扩展库绕过disable_functions，需要使用dl()并且开启这个选项)'),
        ('<td class="e">allow_url_include<\/td><td class="v">On<\/td>', 'allow_url_include: On (可以使用远程文件包含)'),
        ('<td class="e">session.use_trans_sid<\/td><td class="v">1<\/td>', 'session.use_trans_sid: 1'),
        ('<td class="e">display_errors<\/td><td class="v">On<\/td>', 'display_errors: On'),
        ('short_open_tag</td><td class="v">On</td>', 'short_open_tag:On (允许<??>这种形式，并且<?=等价于<? echo)'),
        ('<td class="e">session\.use_only_cookies<\/td><td class="v">Off<\/td>', 'session.use_only_cookies: On'),
        ('System </td><td class="v">(.*?)</td>', "系统信息:{}"),
        ('SCRIPT_FILENAME"]</td><td class="v">(.*?)</td>', '脚本路径:{}'),
        ('SERVER_ADDR"]</td><td class="v">(.*?)</td>', '服务器IP地址:{}'),
        ('disable_functions</td><td class="v">(.*?)</td>', '禁用的函数列表:{}'),
        ('open_basedir</td><td class="v">(.*?)</td>', 'open_basedir(将用户可操作的文件限制在某目录下,但是这个限制是可以绕过的):{}'),
        ('PATH"]</td><td class="v">(.*?)</td>', '环境变量:{}'),
    ]
    ret = []
    for regx, msg in phpinfo_dict:
        r = re.search(regx, html, re.I | re.M | re.S)
        if r:
            if "{}" in msg:
                ret.append(msg.format(r.group(1)))
            else:
                ret.append(msg)

    return ret
