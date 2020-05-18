#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2020/4/24 11:18 AM
# @Author  : w8ay
# @File    : test_json_params.py
from lib.core.common import updateJsonObjectFromStr

base_obj = {
    'action': 'mystr',
    'method': 'update',
    'data': [{
        'userId': 'test123',
        'version': '1',
        'firstName': 'test123',
        'lastName': 'test123',
        'email': 'test123@qq.com',
        'status': 'active',
        'roles': ['aaaa']
    }],
    'type': 'rpc',
    'tid': 10
}

duoceng_obj = {
    "aaa": [
        {
            "username": "",
            "password": ""
        },
        {
            "a2": "",
            "a3": [
                "a", "b", "c"
            ]
        }
    ]
}
update_str = 'update_aaaaaaa'

for tmp in updateJsonObjectFromStr(duoceng_obj, update_str):
    print(tmp)
