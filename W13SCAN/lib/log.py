#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/7/25 10:08 PM
# @Author  : w8ay
# @File    : log.py
import logging

FORMATTER = logging.Formatter("\r[%(asctime)s] [%(levelname)s] %(message)s", "%H:%M:%S")
LOGGER = logging.getLogger('w13scan')
LOGGER.setLevel(logging.INFO)
LOGGER_HANDLER = logging.StreamHandler()
LOGGER_HANDLER.setFormatter(FORMATTER)
LOGGER.addHandler(LOGGER_HANDLER)
