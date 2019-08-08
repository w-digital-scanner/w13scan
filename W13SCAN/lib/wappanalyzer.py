#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/8/8 3:26 PM
# @Author  : w8ay
# @File    : wappanalyzer.py
import json
import os
import re
import warnings

from W13SCAN.lib.const import PROGRAMING, OPERATING_SYSTEM, WEB_SERVER
from W13SCAN.lib.data import PATH


class Wappalyzer(object):
    """
    Python Wappalyzer driver.
    """

    def __init__(self, categories, apps):
        """
        Initialize a new Wappalyzer instance.

        Parameters
        ----------

        categories : dict
            Map of category ids to names, as in apps.json.
        apps : dict
            Map of app names to app dicts, as in apps.json.
        """
        self.categories = categories
        self.apps = apps

        for name, app in self.apps.items():
            self._prepare_app(app)

    @classmethod
    def latest(cls):
        """
        Construct a Wappalyzer instance using a apps db path passed in via
        apps_file, or alternatively the default in data/apps.json
        """
        apps_file = os.path.join(PATH["data"], "wappalyzer.json")
        with open(apps_file, 'r') as fd:
            obj = json.load(fd)
        return cls(categories=obj['categories'], apps=obj['apps'])

    def _prepare_app(self, app):
        """
        Normalize app data, preparing it for the detection phase.
        """

        # Ensure these keys' values are lists
        for key in ['url', 'html', 'script', 'implies']:
            try:
                value = app[key]
            except KeyError:
                app[key] = []
            else:
                if not isinstance(value, list):
                    app[key] = [value]

        # Ensure these keys exist
        for key in ['headers', 'meta']:
            try:
                value = app[key]
            except KeyError:
                app[key] = {}

        # Ensure the 'meta' key is a dict
        obj = app['meta']
        if not isinstance(obj, dict):
            app['meta'] = {'generator': obj}

        # Ensure keys are lowercase
        for key in ['headers', 'meta']:
            obj = app[key]
            app[key] = {k.lower(): v for k, v in obj.items()}

        # Prepare regular expression patterns
        for key in ['url', 'html', 'script']:
            app[key] = [self._prepare_pattern(pattern) for pattern in app[key]]

        for key in ['headers', 'meta']:
            obj = app[key]
            for name, pattern in obj.items():
                obj[name] = self._prepare_pattern(obj[name])

    def _prepare_pattern(self, pattern):
        """
        Strip out key:value pairs from the pattern and compile the regular
        expression.
        """
        regex, _, rest = pattern.partition('\\;')
        try:
            return re.compile(regex, re.I)
        except re.error as e:
            warnings.warn(
                "Caught '{error}' compiling regex: {regex}"
                    .format(error=e, regex=regex)
            )
            # regex that never matches:
            # http://stackoverflow.com/a/1845097/413622
            return re.compile(r'(?!x)x')

    def _has_app(self, app, webpage, headers):
        """
        Determine whether the web page matches the app signature.
        """
        # Search the easiest things first and save the full-text search of the
        # HTML for last

        for regex in app['url']:
            if regex.search(webpage):
                return True

        for name, regex in app['headers'].items():
            if re.search(name, headers, re.I):
                if regex and regex.search(headers):
                    return True

        for regex in app['script']:
            for script in webpage:
                if regex.search(script):
                    return True

        for regex in app['html']:
            if regex.search(webpage):
                return True

    def _get_implied_apps(self, detected_apps):
        """
        Get the set of apps implied by `detected_apps`.
        """

        def __get_implied_apps(apps):
            _implied_apps = set()
            for app in apps:
                try:
                    _implied_apps.update(set(self.apps[app]['implies']))
                except KeyError:
                    pass
            return _implied_apps

        implied_apps = __get_implied_apps(detected_apps)
        all_implied_apps = set()

        # Descend recursively until we've found all implied apps
        while not all_implied_apps.issuperset(implied_apps):
            all_implied_apps.update(implied_apps)
            implied_apps = __get_implied_apps(all_implied_apps)

        return all_implied_apps

    def get_categories(self, app_name):
        """
        Returns a list of the categories for an app name.
        """
        cat_nums = self.apps.get(app_name, {}).get("cats", [])
        cat_names = [self.categories.get("%s" % cat_num, "")
                     for cat_num in cat_nums]

        return cat_names

    def analyze(self, webpage, headers):
        """
        Return a list of applications that can be detected on the web page.
        """
        detected_apps = set()

        for app_name, app in self.apps.items():
            if self._has_app(app, webpage, headers):
                detected_apps.add(app_name)

        detected_apps |= self._get_implied_apps(detected_apps)

        return detected_apps

    def analyze_with_categories(self, webpage, headers):
        """
        Return a list of applications and categories that can be detected on the web page.
        """
        detected_apps = self.analyze(webpage, headers)
        categorised_apps = {}

        for app_name in detected_apps:
            cat_names = self.get_categories(app_name)
            for i in cat_names:
                categorised_apps[i] = app_name

        return categorised_apps


def fingter(html: str, headers: str):
    if len(html) > 1000000:
        html = ''
    wappalyzer = Wappalyzer.latest()
    ret = wappalyzer.analyze_with_categories(html, headers)
    return ret


def fingter_loader(html: str, headers: str):
    ret = fingter(html, headers)
    result = {
        "ProgrammingLanguages": None,
        "OperatingSystems": None,
        "WebServers": None
    }
    if not ret:
        return result["ProgrammingLanguages"], result["OperatingSystems"], result["WebServers"]
        # 编程语言
    if "Programming Languages" in ret:
        if isinstance(ret["Programming Languages"], list):
            ret["Programming Languages"] = ret["Programming Languages"][0]
        if ret["Programming Languages"] in PROGRAMING.values():
            result["ProgrammingLanguages"] = list(PROGRAMING.keys())[list(PROGRAMING.values()).index(ret["Programming Languages"])]

    # 操作系统
    if "Operating Systems" in ret:
        if isinstance(ret["Operating Systems"], list):
            ret["Operating Systems"] = ret["Operating Systems"][0]
        if ret["Operating Systems"] in OPERATING_SYSTEM.values():
            result["OperatingSystems"] = list(OPERATING_SYSTEM.keys())[list(OPERATING_SYSTEM.values()).index(ret["Operating Systems"])]

    # Web Servers
    if "Web Servers" in ret:
        if isinstance(ret["Web Servers"], list):
            ret["Web Servers"] = ret["Web Servers"][0]
        if ret["Web Servers"] in WEB_SERVER.values():
            result["WebServers"] = list(WEB_SERVER.keys())[list(WEB_SERVER.values()).index(ret["Web Servers"])]

    return result["ProgrammingLanguages"], result["OperatingSystems"], result["WebServers"]
