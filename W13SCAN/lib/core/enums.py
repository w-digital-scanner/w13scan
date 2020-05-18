#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2020/3/31 10:51 AM
# @Author  : w8ay
# @File    : enums.py

# We define some constants
class DBMS:
    DB2 = 'IBM DB2 database'
    MSSQL = 'Microsoft SQL database'
    ORACLE = 'Oracle database'
    SYBASE = 'Sybase database'
    POSTGRE = 'PostgreSQL database'
    MYSQL = 'MySQL database'
    JAVA = 'Java connector'
    ACCESS = 'Microsoft Access database'
    INFORMIX = 'Informix database'
    INTERBASE = 'Interbase database'
    DMLDATABASE = 'DML Language database'
    SQLITE = 'SQLite database'
    UNKNOWN = 'Unknown database'


class OS(object):
    LINUX = "Linux"
    WINDOWS = "Windows"
    DARWIN = "Darwin"


class PLACE:
    GET = "GET"
    POST = "POST"
    URI = "URI"
    COOKIE = "Cookie"
    USER_AGENT = "User-Agent"
    REFERER = "Referer"
    HOST = "Host"


class HTTPMETHOD(object):
    GET = "GET"
    POST = "POST"
    HEAD = "HEAD"
    PUT = "PUT"
    DELETE = "DELETE"
    TRACE = "TRACE"
    OPTIONS = "OPTIONS"
    CONNECT = "CONNECT"
    PATCH = "PATCH"


class POST_HINT(object):
    NORMAL = "NORMAL"
    SOAP = "SOAP"
    JSON = "JSON"
    JSON_LIKE = "JSON-like"
    MULTIPART = "MULTIPART"
    XML = "XML (generic)"
    ARRAY_LIKE = "Array-like"


class WEB_PLATFORM(object):
    PHP = "Php"
    ASP = "Asp"
    ASPX = "Aspx"
    JAVA = "Java"
    PYTHON = 'Python'


class Level(object):
    NONE = 0
    LOW = 1
    MIDDLE = 2
    HIGHT = 3


POST_HINT_CONTENT_TYPES = {
    POST_HINT.JSON: "application/json",
    POST_HINT.JSON_LIKE: "application/json",
    POST_HINT.MULTIPART: "multipart/form-data",
    POST_HINT.SOAP: "application/soap+xml",
    POST_HINT.XML: "application/xml",
    POST_HINT.ARRAY_LIKE: "application/x-www-form-urlencoded; charset=utf-8",
}


class VulType(object):
    CMD_INNJECTION = "cmd_injection"
    CODE_INJECTION = "code_injection"
    XSS = "xss"
    SQLI = "sqli"
    DIRSCAN = "dirscan"
    PATH_TRAVERSAL = "path_traversal"
    XXE = "xxe"
    BRUTE_FORCE = "brute_force"
    JSONP = "jsonp"
    SSRF = "ssrf"
    BASELINE = "baseline"
    REDIRECT = "redirect"
    CRLF = "crlf"
    SENSITIVE = "sensitive"
    SMUGGLING = 'smuggling'
