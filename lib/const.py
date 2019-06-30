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
    '.do', ''
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
