<h1 align="center">W13Scan</h1>

> W13scan is a proxy-based web scanner that runs on Linux/Windows/Mac systems.

[简体中文](./README_CN.md) | English

## Begin
Demo https://www.youtube.com/watch?v=zBgfnY-qSTU

Pure Python and Python version > 3

Can you use star to encourage the author ？

## 📦 Install

```bash
pip3 install w13scan
```

## 🔨 Usage

```bash
## help
w13scan -h

## running
w13scan -s 127.0.0.1:7778
```

### HTTPS Support

If you want w13scan to support https, similar to BurpSuite, first need to set up a proxy server (default 127.0.0.1:7778), then go to http://w13scan.ca to download the root certificate and trust it.

## ⌨️ Development

```python
from W13SCAN.api import Scanner

scanner = Scanner(threads=20)
scanner.put("http://example.com/?post=1")
scanner.run()

```

By introducing the w13scan package, you can quickly create a scanner.

