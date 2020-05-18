#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2020/4/8 10:13 AM
# @Author  : w8ay
# @File    : jscontext.py

import pyjsparser
from pyjsparser import parse


class JsParseError(Exception):
    """Exception raised for errors in the input.

    Attributes:
        expression -- input expression in which the error occurred
        message -- explanation of the error
    """

    def __init__(self, expression, message):
        self.expression = expression
        self.message = message


WHITE_SPACE = {0x20, 0x09, 0x0B, 0x0C, 0xA0, 0x1680, 0x180E, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006,
               0x2007, 0x2008, 0x2009, 0x200A, 0x202F, 0x205F, 0x3000, 0xFEFF}

LINE_TERMINATORS = {0x0A, 0x0D, 0x2028, 0x2029}


def isLineTerminator(ch):
    return ch in LINE_TERMINATORS


def isWhiteSpace(ch):
    return ch in WHITE_SPACE


def skipMultiLineComment(index, length, source):
    start = index
    while index < length:
        ch = ord(source[index])
        if isLineTerminator(ch):
            if (ch == 0x0D and ord(source[index + 1]) == 0x0A):
                index += 1
            index += 1
        elif ch == 0x2A:
            # Block comment ends with '*/'.
            if ord(source[index + 1]) == 0x2F:
                index += 2
                return {
                    'type': 'Block',
                    'value': source[start:index - 2],
                }

            index += 1
        else:
            index += 1
    return None


def skipSingleLineComment(offset, index, length, source):
    start = index - offset
    while index < length:
        ch = ord(source[index])
        index += 1
        if isLineTerminator(ch):
            if (ch == 13 and ord(source[index]) == 10):
                index += 1
            return {
                'type': 'Line',
                'value': source[start + offset:index - 1],
            }
    return None


def getComment(scripts):
    '''
    获得JavaScript中注释内容以及注释类型
    :param scripts:
    :return:
    '''
    length = len(scripts)
    index = 0
    start = True
    comments = []
    while index < length:
        ret = None
        ch = ord(scripts[index])
        if isWhiteSpace(ch):
            index += 1
        elif isLineTerminator(ch):
            index += 1
            if (ch == 0x0D and ord(scripts[index]) == 0x0A):
                index += 1
            start = True
        elif (ch == 0x2F):  # U+002F is '/'
            ch = ord(scripts[index + 1])
            if (ch == 0x2F):
                index += 2
                ret = skipSingleLineComment(2, index, length, scripts)
                start = True
            elif (ch == 0x2A):  # U+002A is '*'
                index += 2
                ret = skipMultiLineComment(index, length, scripts)
            else:
                break
        elif (start and ch == 0x2D):  # U+002D is '-'
            # U+003E is '>'
            if (ord(scripts[index + 1]) == 0x2D) and (ord(
                    scripts[index + 2]) == 0x3E):
                # '-->' is a single-line comment
                index += 3
                ret = skipSingleLineComment(3, index, length, scripts)
            else:
                break
        elif (ch == 0x3C):  # U+003C is '<'
            if scripts[index + 1:index + 4] == '!--':
                # <!--
                index += 4
                ret = skipSingleLineComment(4, index, length, scripts)
            else:
                break
        else:
            index += 1
        if ret:
            comments.append(ret)
    return comments


def SearchInputInScript(input, script):
    # 测试是否在js注释中
    comments = getComment(script)
    index = 0
    ret = []
    for comment in comments:
        if input not in comment["value"]:
            continue
        # 在注释中
        _type = comment["type"]
        if _type == "Line":
            # 单行注释
            ret.append({
                "type": "InlineComment",
                "position": index,
                "details": {
                    "tagname": "script",
                    "content": comment["value"],
                    "attibutes": []
                }
            })
        elif _type == "Block":
            # 多行注释
            ret.append({
                "type": "BlockComment",
                "position": index,
                "details": {
                    "tagname": "script",
                    "content": comment["value"],
                    "attibutes": []
                }
            })
        index += 1

    try:
        nodes = parse(script)
    except pyjsparser.pyjsparserdata.JsSyntaxError as e:
        return []
    index = 0
    for node in nodes["body"]:
        found = analyse(input, node)
        if found:
            ret.append({
                "type": found["type"],
                "position": index,
                "details": {
                    "tagname": "script",
                    "content": found["value"],
                    "attibutes": []
                }
            })
        index += 1
    return ret


def analyse(input, node: dict):
    if node.get("type", "") == "Identifier":
        name = getIdentifier(node)
        if input in name:
            return {
                "type": "ScriptIdentifier",
                "value": name
            }
    elif node.get("type", "") == "Literal":
        name = getLiteral(node)
        if input in name:
            return {
                "type": "ScriptLiteral",
                "value": name
            }
    else:
        for k, v in node.items():
            if isinstance(v, dict):
                found = analyse(input, v)
                if found:
                    return found
            elif isinstance(v, list):
                for i in v:
                    if isinstance(i, dict):
                        found = analyse(input, i)
                        if found:
                            return found
            else:
                if input in str(v):
                    return {
                        "type": "Script" + node["type"],
                        "value": str(v)
                    }


def getIdentifier(node: dict):
    if node.get("type", "") == "Identifier":
        return node.get("name", "")
    return ""


def getLiteral(node: dict):
    if node.get("type", "") == "Literal":
        return node.get("raw", "")
    return ""


def analyse_js(node) -> list:
    if isinstance(node, dict):
        r = []
        if node.get("type") == "VariableDeclarator":
            id = node.get("id", {})
            if isinstance(id, dict):
                if id.get("type") == "Identifier":
                    r.append(id["name"])

        for key, value in node.items():
            dd = analyse_js(value)
            r.extend(dd)
        return r
    elif isinstance(node, list):
        r = []
        for item in node:
            r.extend(analyse_js(item))
        return r
    return []


def analyse_Literal(node) -> list:
    if isinstance(node, dict):
        r = []
        if node.get("type") == "Literal":
            value = node.get("value", None)
            if value:
                r.append(str(value))

        for key, value in node.items():
            dd = analyse_Literal(value)
            r.extend(dd)
        return r
    elif isinstance(node, list):
        r = []
        for item in node:
            r.extend(analyse_Literal(item))
        return r
    return []
