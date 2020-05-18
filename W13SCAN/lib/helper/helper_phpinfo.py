#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/11 4:32 PM
# @Author  : w8ay
# @File    : phpinfo_helper.py

import re


def get_phpinfo(html) -> list:
    phpinfo_dict = [
        ('<td class="e">allow_url_fopen<\/td><td class="v">On<\/td>', 'allow_url_fopen: On'),
        ('<td class="e">register_globals<\/td><td class="v">On<\/td>', 'register_globals: On'),
        ('<td class="e">allow_url_include<\/td><td class="v">On<\/td>', 'allow_url_include: On'),
        ('<td class="e">session.use_trans_sid<\/td><td class="v">1<\/td>', 'session.use_trans_sid: 1'),
        ('<td class="e">open_basedir<\/td><td class="v"><i>no value<\/i><\/td>', 'open_basedir: no value'),
        ('<td class="e">display_errors<\/td><td class="v">On<\/td>', 'display_errors: On'),
        ('<td class="e">session\.use_only_cookies<\/td><td class="v">Off<\/td>', 'session.use_only_cookies: On'),
        ('System </td><td class="v">(.*?)</td>', "System:{}"),
        ('SCRIPT_FILENAME"]</td><td class="v">(.*?)</td>', 'Path:{}'),
        ('SERVER_ADDR"]</td><td class="v">(.*?)</td>', 'IP:{}'),
        ('disable_functions</td><td class="v">(.*?)</td>', 'disable_functions:{}'),
        ('short_open_tag</td><td class="v">(.*?)</td>', 'short_open_tag:{}'),
        ('PATH"]</td><td class="v">(.*?)</td>', 'Env:{}'),
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
