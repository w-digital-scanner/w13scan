#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/6/28 10:01 PM
# @Author  : w8ay
# @File    : common.py
import base64
import binascii
import hashlib
import json
import random
import re
import string
import sys
from urllib.parse import urlparse, urljoin, quote

import requests

from W13SCAN.lib.const import PLACE, DEFAULT_GET_POST_DELIMITER, DEFAULT_COOKIE_DELIMITER, POST_HINT, \
    GITHUB_REPORT_OAUTH_TOKEN


def dataToStdout(data, bold=False):
    """
    Writes text to the stdout (console) stream
    """

    sys.stdout.write(data)

    try:
        sys.stdout.flush()
    except IOError:
        pass

    return


def get_parent_paths(path, domain=True):
    '''
    通过一个链接分离出各种目录
    :param path:
    :param domain:
    :return:
    '''
    netloc = ''
    if domain:
        p = urlparse(path)
        path = p.path
        netloc = "{}://{}".format(p.scheme, p.netloc)
    paths = []
    if not path or path[0] != '/':
        return paths
    # paths.append(path)
    if path[-1] == '/':
        paths.append(netloc + path)
    tph = path
    if path[-1] == '/':
        tph = path[:-1]
    while tph:
        tph = tph[:tph.rfind('/') + 1]
        paths.append(netloc + tph)
        tph = tph[:-1]
    return paths


def get_links(content, domain, limit=True):
    '''
    从网页源码中匹配链接
    :param content: html源码
    :param domain: 当前网址domain
    :param limit: 是否限定于此域名
    :return:
    '''
    p = urlparse(domain)
    netloc = "{}://{}{}".format(p.scheme, p.netloc, p.path)
    match = re.findall(r'''(href|src)=["'](.*?)["']''', content, re.S | re.I)
    urls = []
    for i in match:
        _domain = urljoin(netloc, i[1])
        if limit:
            if p.netloc.split(":")[0] not in _domain:
                continue
        urls.append(_domain)
    return urls


def random_str(length=10, chars=string.ascii_letters + string.digits):
    return ''.join(random.sample(chars, length))


def md5(src):
    m2 = hashlib.md5()
    m2.update(src)
    return m2.hexdigest()


def get_middle_text(text, prefix, suffix, index=0):
    """
    获取中间文本的简单实现

    :param text:要获取的全文本
    :param prefix:要获取文本的前部分
    :param suffix:要获取文本的后半部分
    :param index:从哪个位置获取
    :return:
    """
    try:
        index_1 = text.index(prefix, index)
        index_2 = text.index(suffix, index_1 + len(prefix))
    except ValueError:
        # logger.log(CUSTOM_LOGGING.ERROR, "text not found pro:{} suffix:{}".format(prefix, suffix))
        return ''
    return text[index_1 + len(prefix):index_2]


def prepare_url(url, params):
    req = requests.Request('GET', url, params=params)
    r = req.prepare()
    return r.url


def paramToDict(parameters, place=PLACE.GET, hint=POST_HINT.NORMAL) -> dict:
    """
    Split the parameters into names and values, check if these parameters
    are within the testable parameters and return in a dictionary.
    """

    testableParameters = {}
    if place == PLACE.COOKIE:
        splitParams = parameters.split(DEFAULT_COOKIE_DELIMITER)
        hint = POST_HINT.NORMAL
        for element in splitParams:
            parts = element.split("=")
            if len(parts) >= 2:
                testableParameters[parts[0]] = ''.join(parts[1:])
    # elif (place == PLACE.GET or PLACE == PLACE.POST) and (hint == POST_HINT.NORMAL or hint == POST_HINT.ARRAY_LIKE):
    #     splitParams = parameters.split(DEFAULT_GET_POST_DELIMITER)
    elif place == PLACE.GET:
        splitParams = parameters.split(DEFAULT_GET_POST_DELIMITER)
        for element in splitParams:
            parts = element.split("=")
            if len(parts) >= 2:
                testableParameters[parts[0]] = ''.join(parts[1:])
    elif place == PLACE.POST:
        if hint == POST_HINT.NORMAL:
            splitParams = parameters.split(DEFAULT_GET_POST_DELIMITER)
            for element in splitParams:
                parts = element.split("=")
                if len(parts) >= 2:
                    testableParameters[parts[0]] = ''.join(parts[1:])
        elif hint == POST_HINT.JSON:
            try:
                data = json.loads(parameters)
                if isListLike(data):
                    for i in data:
                        testableParameters[i] = ''
                elif isinstance(data, dict):
                    testableParameters.update(data)
            except json.decoder.JSONDecodeError:
                pass
            except:
                pass
        elif hint == POST_HINT.ARRAY_LIKE:
            splitParams = parameters.split(DEFAULT_GET_POST_DELIMITER)
            for element in splitParams:
                parts = element.split("=")
                if len(parts) >= 2:
                    key = parts[0]
                    value = ''.join(parts[1:])
                    if key in testableParameters:
                        testableParameters[key] = [testableParameters[key]]
                        testableParameters[key].append(value)
                    else:
                        testableParameters[key] = value
    return testableParameters


def postParamsCombination(data, hint=POST_HINT.NORMAL):
    """
    组合POST参数,将相关类型参数组合成requests认识的

    :param data:
    :param hint:
    :return:
    """
    if hint == POST_HINT.NORMAL:
        return data
    elif hint == POST_HINT.JSON:
        return json.dumps(data)
    elif hint == POST_HINT.ARRAY_LIKE:
        return data


def isListLike(value):
    """
    Returns True if the given value is a list-like instance

    >>> isListLike([1, 2, 3])
    True
    >>> isListLike('2')
    False
    """

    return isinstance(value, (list, tuple, set))


def findMultipartPostBoundary(post):
    """
    Finds value for a boundary parameter in given multipart POST body

    >>> findMultipartPostBoundary("-----------------------------9051914041544843365972754266\\nContent-Disposition: form-data; name=text\\n\\ndefault")
    '9051914041544843365972754266'
    """

    retVal = None

    done = set()
    candidates = []

    for match in re.finditer(r"(?m)^--(.+?)(--)?$", post or ""):
        _ = match.group(1).strip().strip('-')

        if _ in done:
            continue
        else:
            candidates.append((post.count(_), _))
            done.add(_)

    if candidates:
        candidates.sort(key=lambda _: _[0], reverse=True)
        retVal = candidates[0][1]

    return retVal


def is_base64(value: str):
    """
    成功返回解码后的值，失败返回False
    :param value:
    :return:
    """
    regx = '^[a-zA-Z0-9\+\/=\%]+$'
    if not re.match(regx, value):
        return False
    try:
        ret = base64.b16decode(value).decode(errors='ignore')
    except binascii.Error:
        return False
    return ret


def isJavaObjectDeserialization(value):
    if len(value) < 10:
        return False
    if value[0:5].lower() == "ro0ab":
        ret = is_base64(value)
        if not ret:
            return False
        if bytes(ret).startswith(bytes.fromhex("ac ed 00 05")):
            return True
    return False


def isPHPObjectDeserialization(value: str):
    if len(value) < 10:
        return False
    if value.startswith("O:") or value.startswith("a:"):
        if re.match('^[O]:\d+:"[^"]+":\d+:{.*}', value) or re.match('^a:\d+:{(s:\d:"[^"]+";|i:\d+;).*}', value):
            return True
    elif (value.startswith("Tz") or value.startswith("YT")) and is_base64(value):
        ret = is_base64(value)
        if re.match('^[O]:\d+:"[^"]+":\d+:{.*}', value) or re.match('^a:\d+:{(s:\d:"[^"]+";|i:\d+;).*}', ret):
            return True
    return False


def isPythonObjectDeserialization(value: str):
    if len(value) < 10:
        return False
    ret = is_base64(value)
    if not ret:
        return False
    # pickle binary
    if value.startswith("g"):
        if bytes(ret).startswith(bytes.fromhex("8003")) and ret.endswith("."):
            return True

    # pickle text versio
    elif value.startswith("K"):
        if (ret.startswith("(dp1") or ret.startswith("(lp1")) and ret.endswith("."):
            return True
    return False


def createGithubIssue(errMsg, excMsg):
    _ = re.sub(r"'[^']+'", "''", excMsg)
    _ = re.sub(r"\s+line \d+", "", _)
    _ = re.sub(r'File ".+?/(\w+\.py)', r"\g<1>", _)
    _ = re.sub(r".+\Z", "", _)
    _ = re.sub(r"(Unicode[^:]*Error:).+", r"\g<1>", _)
    _ = re.sub(r"= _", "= ", _)
    errMsg = re.sub("cookie: .*", 'cookie: *', errMsg, flags=re.I | re.S)

    key = hashlib.md5(_.encode()).hexdigest()[:8]
    try:
        req = requests.get("https://api.github.com/search/issues?q={}".format(
            quote("repo:w-digital-scanner/w13scan Unhandled exception (#{})".format(key))))
    except Exception as e:
        return False
    _ = json.loads(req.text)
    try:
        duplicate = _["total_count"] > 0
        closed = duplicate and _["items"][0]["state"] == "closed"
        if duplicate:
            warnMsg = "issue seems to be already reported"
            if closed:
                warnMsg += " and resolved. Please update to the latest "
            dataToStdout('\r' + "[x] {}".format(warnMsg) + '\n\r')
            return False
    except KeyError:
        return False
    data = {
        "title": "Unhandled exception (#{})".format(key),
        "body": "```\n%s\n```\n```\n%s\n```" % (errMsg, excMsg),
        "labels": ["bug"]
    }

    headers = {
        "Authorization": "token {}".format(base64.b64decode(GITHUB_REPORT_OAUTH_TOKEN.encode()).decode())
    }
    try:
        r = requests.post("https://api.github.com/repos/w-digital-scanner/w13scan/issues", data=json.dumps(data),
                          headers=headers)
    except Exception as e:
        return False
    issueUrl = re.search(r"https://github\.com/w-digital-scanner/w13scan/issues/\d+", r.text)
    if issueUrl:
        infoMsg = "created Github issue can been found at the address '%s'" % issueUrl.group(0)
        dataToStdout('\r' + "[*] {}".format(infoMsg) + '\n\r')
        return True
    return False
