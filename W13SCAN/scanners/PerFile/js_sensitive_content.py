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

        regx = {
            # 匹配url
            # r'(\b|\'|")(?:http:|https:)(?:[\w/\.]+)?(?:[a-zA-Z0-9_\-\.]{1,})\.(?:php|asp|ashx|jspx|aspx|jsp|json|action|html|txt|xml|do)(\b|\'|")',
            # 匹配邮箱
            "邮箱信息": r'[a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)+',
            # 匹配token或者密码泄露
            # 例如token = xxxxxxxx, 或者"apikey" : "xssss"
            "Token或密码": r'\b(?:secret|secret_key|token|secret_token|auth_token|access_token|username|password|aws_access_key_id|aws_secret_access_key|secretkey|authtoken|accesstoken|access-token|authkey|client_secret|bucket|email|HEROKU_API_KEY|SF_USERNAME|PT_TOKEN|id_dsa|clientsecret|client-secret|encryption-key|pass|encryption_key|encryptionkey|secretkey|secret-key|bearer|JEKYLL_GITHUB_TOKEN|HOMEBREW_GITHUB_API_TOKEN|api_key|api_secret_key|api-key|private_key|client_key|client_id|sshkey|ssh_key|ssh-key|privatekey|DB_USERNAME|oauth_token|irc_pass|dbpasswd|xoxa-2|xoxrprivate-key|private_key|consumer_key|consumer_secret|access_token_secret|SLACK_BOT_TOKEN|slack_api_token|api_token|ConsumerKey|ConsumerSecret|SESSION_TOKEN|session_key|session_secret|slack_token|slack_secret_token|bot_access_token|passwd|api|eid|sid|api_key|apikey|userid|user_id|user-id)["\s]*(?::|=|=:|=>)["\s]*[a-z0-9A-Z]{8,64}"?',
            # 匹配IP地址
            "IP地址": r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
            # 匹配云泄露
            "Cloudfront云泄露": r'[\w]+\.cloudfront\.net',
            "Appspot云泄露": r'[\w\-.]+\.appspot\.com',
            "亚马逊云泄露": r'[\w\-.]*s3[\w\-.]*\.?amazonaws\.com\/?[\w\-.]*',
            "Digitalocean云泄露": r'([\w\-.]*\.?digitaloceanspaces\.com\/?[\w\-.]*)',
            "Google云泄露": r'(storage\.cloud\.google\.com\/[\w\-.]+)',
            "Google存储API泄露": r'([\w\-.]*\.?storage.googleapis.com\/?[\w\-.]*)',
            # 匹配手机号
            "手机号": r'(?:139|138|137|136|135|134|147|150|151|152|157|158|159|178|182|183|184|187|188|198|130|131|132|155|156|166|185|186|145|175|176|133|153|177|173|180|181|189|199|170|171)[0-9]{8}',
            # 匹配域名
            # "域名泄露": r'((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:biz|cc|club|cn|com|co|edu|fun|group|info|ink|kim|link|live|ltd|mobi|net|online|org|pro|pub|red|ren|shop|site|store|tech|top|tv|vip|wang|wiki|work|xin|xyz|me))',

            # SSH 密钥
            "SSH密钥": '([-]+BEGIN [^\\s]+ PRIVATE KEY[-]+[\\s]*[^-]*[-]+END [^\\s]+ '
                     'PRIVATE KEY[-]+)',

            # access_key
            "Access Key": 'access_key.*?["\'](.*?)["\']',
            "Access Key ID 1": 'accesskeyid.*?["\'](.*?)["\']',
            "Access Key ID 2": 'accesskeyid.*?["\'](.*?)["\']',

            # 亚马逊 aws api 账号 密钥
            "亚马逊AWS API": 'AKIA[0-9A-Z]{16}',
            "亚马逊AWS 3S API 1": 's3\\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\\.s3\\.amazonaws.com',
            "亚马逊AWS 3S API 2": '([a-zA-Z0-9-\\.\\_]+\\.s3\\.amazonaws\\.com|s3://[a-zA-Z0-9-\\.\\_]+|s3-[a-zA-Z0-9-\\.\\_\\/]+|s3.amazonaws.com/[a-zA-Z0-9-\\.\\_]+|s3.console.aws.amazon.com/s3/buckets/[a-zA-Z0-9-\\.\\_]+)',
            "亚马逊AWS 3S API 3": 'amzn\\\\.mws\\\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',

            # author 信息
            "作者信息": '@author[: ]+(.*?) ',
            "API": 'api[key|_key|\\s+]+[a-zA-Z0-9_\\-]{5,100}',
            "基础信息": 'basic [a-zA-Z0-9=:_\\+\\/-]{5,100}',
            "Bearer": 'bearer [a-zA-Z0-9_\\-\\.=:_\\+\\/]{5,100}',

            # facebook token
            "Facebook Token": 'EAACEdEose0cBA[0-9A-Za-z]+',
            # github token
            "Github Token": '[a-zA-Z0-9_-]*:[a-zA-Z0-9_\\-]+@github\\.com*',
            # google api
            "Google API": 'AIza[0-9A-Za-z-_]{35}',
            # google captcha 验证
            "Google验证码": '6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$',
            # google oauth 权限
            "Google OAuth": 'ya29\\.[0-9A-Za-z\\-_]+',
            # jwt
            "JWT鉴权": 'ey[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.?[A-Za-z0-9-_.+/=]*$',
            # mailgun 服务密钥
            "Mailgun服务密钥": 'key-[0-9a-zA-Z]{32}',
            # paypal braintree 访问凭证
            "Paypal/Braintree访问凭证": 'access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}',
            # PGP 密钥块
            "PGP密钥": '-----BEGIN PGP PRIVATE KEY BLOCK-----',
            # possible_creds
            "密码泄露": '(?i)(password\\s*[`=:\\"]+\\s*[^\\s]+|password '
                    'is\\s*[`=:\\"]*\\s*[^\\s]+|pwd\\s*[`=:\\"]*\\s*[^\\s]+|passwd\\s*[`=:\\"]+\\s*[^\\s]+)',

            # RSA
            "RSA密钥": '-----BEGIN EC PRIVATE KEY-----',
            # DSA
            "DSA密钥": '-----BEGIN DSA PRIVATE KEY-----',
            # stripe 账号泄露
            "Stripe账号泄露 1": 'rk_live_[0-9a-zA-Z]{24}',
            "Stripe账号泄露 2": 'sk_live_[0-9a-zA-Z]{24}',
            # twillio 账号泄露
            "Twillio 账号泄露 1": 'AC[a-zA-Z0-9_\\-]{32}',
            "Twillio 账号泄露 2": 'SK[0-9a-fA-F]{32}',
            "Twillio 账号泄露 3": 'AP[a-zA-Z0-9_\\-]{32}'
        }
        for name, _ in regx.items():
            texts = re.findall(_, self.response.text, re.M | re.I)
            issuc = False
            if texts:
                for text in set(texts):
                    ignores = ['function', 'encodeURIComponent', 'XMLHttpRequest']
                    is_continue = True

                    for i in ignores:
                        if i in text:
                            is_continue = False
                            break
                    if not is_continue:
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
