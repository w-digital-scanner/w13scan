<h1 align="center">W13Scan</h1>

> W13scan is a proxy-based web scanner that runs on Linux/Windows/Mac systems.

[![GitHub issues](https://img.shields.io/github/issues/boy-hack/w13scan)](https://github.com/boy-hack/w13scan/issues) [![GitHub forks](https://img.shields.io/github/forks/boy-hack/w13scan)](https://github.com/boy-hack/w13scan/network) [![GitHub stars](https://img.shields.io/github/stars/boy-hack/w13scan)](https://github.com/boy-hack/w13scan/stargazers) [![GitHub license](https://img.shields.io/github/license/boy-hack/w13scan)](https://github.com/boy-hack/w13scan/blob/master/LICENSE)

[简体中文](./README_CN.md) | English

## 声明
仅用于教育行为使用，其他用途后果自负

## Begin
Demo https://youtu.be/WwIc2kDlKbc

Pure Python and Python version >= 3

Can you use star to encourage the author ？

## 📦 Install

```bash
$ sudo pip3 install w13scan

## update
$ sudo pip3 install -U w13scan
```
or
```bash
$ wget https://github.com/boy-hack/w13scan/archive/master.zip
$ unzip master.zip
$ cd master/W13SCAN
$ pip3 install -r ../requirement.txt
$ python3 cli.py -h
```

## 🔨 Usage

```bash
## help
$ w13scan -h

## running
$ w13scan -s 127.0.0.1:7778
```

### HTTPS Support

If you want w13scan to support https, similar to BurpSuite, first need to set up a proxy server (default 127.0.0.1:7778), then go to http://w13scan.ca to download the root certificate and trust it.

## ⌨ Development

```python
from W13SCAN.api import Scanner

scanner = Scanner(threads=20)
scanner.put("http://example.com/?post=1")
scanner.run()

```

By introducing the w13scan package, you can quickly create a scanner.

## Contributors
- [CONTRIBUTORS](CONTRIBUTORS.md)
