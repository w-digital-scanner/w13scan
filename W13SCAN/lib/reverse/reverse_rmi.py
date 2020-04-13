#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2020/4/5 12:33 AM
# @File    : reverse_rmi.py

import socket
import threading
import struct
import time
import binascii

from config import REVERSE_RMI_IP, REVERSE_RMI_PORT
from lib.reverse.lib import rlog, reverse_records, reverse_lock


def decode_rmi(query):
    info = ""
    try:
        info = binascii.a2b_hex(query[4:].encode()).decode()
    except Exception as ex:
        rlog.warning("decode rmi error:{} sourquery:{}".format(ex, query))
    return info


def rmi_response(client, address):
    try:
        client.settimeout(30)
        buf = client.recv(1024)
        if b"\x4a\x52\x4d\x49" in buf:
            send_data = b"\x4e"
            send_data += struct.pack(">h", len(address[0]))
            send_data += address[0].encode()
            send_data += b"\x00\x00"
            send_data += struct.pack(">H", address[1])
            client.send(send_data)

            total = 3  # 防止socket的recv接收数据不完整
            buf1 = b""
            while total:
                buf1 += client.recv(512)
                if len(buf1) > 50:
                    break
            if buf1:
                path = bytearray(buf1).split(b"\xdf\x74")[-1][2:].decode(errors="ignore")
                rlog.info("client:{} send path:{}".format(address, path))
                res = {}
                res["type"] = "dns"
                res["client"] = address[0]
                res["query"] = path
                res["info"] = decode_rmi(path)
                res["time"] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
                rlog.info("Insert to db:" + str(res))
                # insert_db(res)
                reverse_lock.acquire()
                reverse_records.append(res)
                reverse_lock.release()
    except Exception as ex:
        rlog.warning('Run rmi error:{} address:{}'.format(ex, address))
    finally:
        client.close()


def rmi_start():
    max_conn = 200
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ip_port = (REVERSE_RMI_IP, int(REVERSE_RMI_PORT))
    sock.bind(ip_port)
    sock.listen(max_conn)
    rlog.info("RMI listen rmi://{}:{}".format(REVERSE_RMI_IP, REVERSE_RMI_PORT))
    while True:
        client, address = sock.accept()
        thread = threading.Thread(target=rmi_response, args=(client, address))
        thread.setDaemon(True)
        thread.start()
