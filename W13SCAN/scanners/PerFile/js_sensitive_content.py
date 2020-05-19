#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/6 9:55 PM
# @Author  : w8ay
# @File    : sensitive_content.py
# referer:https://github.com/al0ne/Vxscan/blob/master/lib/jsparse.py
import re

from lib.core.enums import VulType, PLACE
from lib.core.output import ResultObject
from lib.core.plugins import PluginBase


class W13SCAN(PluginBase):
    name = 'js文件敏感内容匹配'
    desc = '''从返回js的包中匹配敏感内容'''

    def audit(self):
        if self.requests.suffix != ".js":
            return

        regx = [
            # 匹配url
            # r'(\b|\'|")(?:http:|https:)(?:[\w/\.]+)?(?:[a-zA-Z0-9_\-\.]{1,})\.(?:php|asp|ashx|jspx|aspx|jsp|json|action|html|txt|xml|do)(\b|\'|")',
            # 匹配邮箱
            r'[a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)+',
            # 匹配token或者密码泄露
            # 例如token = xxxxxxxx, 或者"apikey" : "xssss"
            r'\b(?:secret|secret_key|token|secret_token|auth_token|access_token|username|password|aws_access_key_id|aws_secret_access_key|secretkey|authtoken|accesstoken|access-token|authkey|client_secret|bucket|email|HEROKU_API_KEY|SF_USERNAME|PT_TOKEN|id_dsa|clientsecret|client-secret|encryption-key|pass|encryption_key|encryptionkey|secretkey|secret-key|bearer|JEKYLL_GITHUB_TOKEN|HOMEBREW_GITHUB_API_TOKEN|api_key|api_secret_key|api-key|private_key|client_key|client_id|sshkey|ssh_key|ssh-key|privatekey|DB_USERNAME|oauth_token|irc_pass|dbpasswd|xoxa-2|xoxrprivate-key|private_key|consumer_key|consumer_secret|access_token_secret|SLACK_BOT_TOKEN|slack_api_token|api_token|ConsumerKey|ConsumerSecret|SESSION_TOKEN|session_key|session_secret|slack_token|slack_secret_token|bot_access_token|passwd|api|eid|sid|api_key|apikey|userid|user_id|user-id)["\s]*(?::|=|=:|=>)["\s]*[a-z0-9A-Z]{8,64}"?',
            # 匹配IP地址
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
            # 匹配云泄露
            r'[\w]+\.cloudfront\.net',
            r'[\w\-.]+\.appspot\.com',
            r'[\w\-.]*s3[\w\-.]*\.?amazonaws\.com\/?[\w\-.]*',
            r'([\w\-.]*\.?digitaloceanspaces\.com\/?[\w\-.]*)',
            r'(storage\.cloud\.google\.com\/[\w\-.]+)',
            r'([\w\-.]*\.?storage.googleapis.com\/?[\w\-.]*)',
            # 匹配手机号
            r'(?:139|138|137|136|135|134|147|150|151|152|157|158|159|178|182|183|184|187|188|198|130|131|132|155|156|166|185|186|145|175|176|133|153|177|173|180|181|189|199|170|171)[0-9]{8}'
            # 匹配域名
            r'((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:biz|cc|club|cn|com|co|edu|fun|group|info|ink|kim|link|live|ltd|mobi|net|online|org|pro|pub|red|ren|shop|site|store|tech|top|tv|vip|wang|wiki|work|xin|xyz|me))',
        ]
        for _ in regx:
            texts = re.findall(_, self.response.text, re.M | re.I)
            issuc = False
            if texts:
                for text in set(texts):
                    ignores = ['function', 'encodeURIComponent', 'XMLHttpRequest']
                    iscontinue = True

                    for i in ignores:
                        if i in text:
                            iscontinue = False
                            break
                    if not iscontinue:
                        continue

                    result = ResultObject(self)
                    result.init_info(self.requests.url, "js文件中存在敏感信息", VulType.SENSITIVE)
                    result.add_detail("payload探测", self.requests.raw, self.response.raw,
                                      "根据正则:{} 发现敏感信息:{}".format(_, text), "", "", PLACE.GET)
                    self.success(result)
                    issuc = True
                    break
            if issuc:
                break
