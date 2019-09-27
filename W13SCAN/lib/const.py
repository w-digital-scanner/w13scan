#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/6/30 11:15 AM
# @Author  : w8ay
# @File    : const.py


acceptedExt = [
    '.php', '.php3', '.php4', '.php5', '.php7', '.phtml',
    '.asp', '.aspx', '.ascx', '.asmx',
    '.chm', '.cfc', '.cfmx', '.cfml',
    '.py',
    '.rb',
    '.pl',
    '.cgi',
    '.jsp', '.jhtml', '.jhtm', '.jws',
    '.htm', '.html',
    '.do', '.action',''
]

ignoreParams = [
    'submit',
    '_',
    '_t',
    'rand',
    'hash'
]

logoutParams = [
    'logout',
    'log_out',
    'loginesc',
    'loginout',
    'delete',
    'signout',
    'logoff',
    'signoff',
    'exit',
    'quit',
    'byebye',
    'bye-bye',
    'clearuser',
    'invalidate',
    'reboot',
    'shutdown',
]


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


class PLACE:
    GET = "GET"
    POST = "POST"
    URI = "URI"
    COOKIE = "Cookie"
    USER_AGENT = "User-Agent"
    REFERER = "Referer"
    HOST = "Host"
    CUSTOM_POST = "(custom) POST"
    CUSTOM_HEADER = "(custom) HEADER"


class POST_HINT(object):
    NORMAL = "NORMAL"
    SOAP = "SOAP"
    JSON = "JSON"
    JSON_LIKE = "JSON-like"
    MULTIPART = "MULTIPART"
    XML = "XML (generic)"
    ARRAY_LIKE = "Array-like"


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

GITHUB_REPORT_OAUTH_TOKEN = "NTYzYjhmZWJjYzc0Njg2ODJhNzhmNDg1YzM0YzlkYjk3N2JiMzE3Nw=="
# sqlmap report

# Default delimiter in cookie values
DEFAULT_COOKIE_DELIMITER = ';'

# Default delimiter in GET/POST values
DEFAULT_GET_POST_DELIMITER = '&'

# Regular expression for XML POST data
XML_RECOGNITION_REGEX = r"(?s)\A\s*<[^>]+>(.+>)?\s*\Z"

# Regular expression used for detecting JSON POST data
JSON_RECOGNITION_REGEX = r'(?s)\A(\s*\[)*\s*\{.*"[^"]+"\s*:\s*("[^"]*"|\d+|true|false|null).*\}\s*(\]\s*)*\Z'

# Regular expression used for detecting JSON-like POST data
JSON_LIKE_RECOGNITION_REGEX = r"(?s)\A(\s*\[)*\s*\{.*'[^']+'\s*:\s*('[^']+'|\d+).*\}\s*(\]\s*)*\Z"

# Regular expression used for detecting multipart POST data
MULTIPART_RECOGNITION_REGEX = r"(?i)Content-Disposition:[^;]+;\s*name="

# Regular expression used for detecting Array-like POST data
ARRAY_LIKE_RECOGNITION_REGEX = r"(\A|%s)(\w+)\[\]=.+%s\2\[\]=" % (
    DEFAULT_GET_POST_DELIMITER, DEFAULT_GET_POST_DELIMITER)

notAcceptedExt = [
    "js",
    "css",
    "jpg",
    "jpeg",
    "png",
    "gif",
    "wmv",
    "a3c",
    "ace",
    "aif",
    "aifc",
    "aiff",
    "arj",
    "asf",
    "asx",
    "attach",
    "au",
    "avi",
    "bin",
    "bmp",
    "cab",
    "cache",
    "class",
    "djv",
    "djvu",
    "dwg",
    "es",
    "esl",
    "exe",
    "fif",
    "fvi",
    "gz",
    "hqx",
    "ice",
    "ico",
    "ief",
    "ifs",
    "iso",
    "jar",
    "jpe",
    "kar",
    "mdb",
    "mid",
    "midi",
    "mov",
    "movie",
    "mp",
    "mp2",
    "mp3",
    "mp4",
    "mpeg",
    "mpeg2",
    "mpg",
    "mpg2",
    "mpga",
    "msi",
    "pac",
    "pdf",
    "ppt",
    "psd",
    "qt",
    "ra",
    "ram",
    "rar",
    "rm",
    "rpm",
    "snd",
    "svf",
    "tar",
    "tgz",
    "tif",
    "tiff",
    "tpl",
    "ttf",
    "uff",
    "wav",
    "wma",
    "zip"
]

WEB_SERVER = {
    "APACHE": "Apache",
    "TOMCAT": "Apache Tomcat",
    "EXPRESS": "Express",
    "FLASK": "Flask",
    "IIS": "IIS",
    "JBOSS": "JBoss Application Server",
    "NGINX": "Nginx",
    "OPENRESTY": "OpenResty",
    "TENGINE": "Tengine",
    "TORNADO": "TornadoServer",
    "GUNICORN": "gunicorn",
    "LIGHTTPD": "lighttpd",
}

PROGRAMING = {
    "C++": "C++",
    "CFML": "CFML",
    "ERLANG": "Erlang",
    "HASKELL": "Haskell",
    "JAVA": "Java",
    "LUA": "Lua",
    "NODEJS": "Node.js",
    "PHP": "PHP",
    "PERL": "Perl",
    "PYTHON": "Python",
    "RUBY": "Ruby",
    "SCALA": "Scala",
    "ASP": "Asp",
    "ASPX": "Aspx"
}

OPERATING_SYSTEM = {
    "WINDOWS": ["Windows Server", "Windows CE"],
    "*NIX": ["CentOS", "Darwin", "Debian", "Fedora", "FreeBSD", "Red Hat", "SUSE", "Scientific Linux"
                                                                                   "SunOS", "UNIX", "Ubuntu"]
}
