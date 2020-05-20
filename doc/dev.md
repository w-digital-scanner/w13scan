## 资源整合能力
w13scan整合了许多开源扫描器，但并不是直接拿来用，而是充分学习了开源扫描器的精华后，将其先进的扫描技术与payload整合到了其中。下列列表详细列举了整合的扫描器：
- sqlmap(https://github.com/sqlmapproject/sqlmap) w13scan sql注入模块(报错注入，布尔注入)
- wascan 一些指纹识别数据

## fingprints指纹数据
`W13SCAN/fingprints`目录下按照指纹类别定义有`framework`,`os`,`programing`,`webserver`
新增指纹需要根据类别在该目录下新增一个python文件，并定义`fingerprint`函数，函数有两个参数`headers`字典型，为header头字典,`content`为当前网页源码,成功返回指纹字符串，多个指纹可返回一个列表。
```python
#!/usr/bin/env python 
# -*- coding:utf-8 -*-
#
# @name:    Python
# @author:  w8ay
from re import search, I, compile, error
def _prepare_pattern(pattern):
    """
    Strip out key:value pairs from the pattern and compile the regular
    expression.
    """
    regex, _, rest = pattern.partition('\;')
    try:
        return compile(regex, I)
    except error as e:
        return compile(r'(?!x)x')
def fingerprint(headers:dict, content:str):
    _ = False
    if 'server' in headers.keys():
        _ |= search(r"(?:^|\s)Python(?:/([\d.]+))?\;version:\1", headers["server"], I) is not None
    if _: return "Python"
```

## 漏洞插件
### 目录结构
`scanners`目录为扫描插件库，每个目录的插件会处理不同情形
- PerFile 针对每个文件，包括参数啥的
- PerFolder 针对url的目录，会分隔目录分别访问
- PerServer 对每个domain的

### FakeReq
继承`PluginBase`类的插件可以使用`self.requests`和`self.response`来获取请求包和返回包，它们分别是`FakeReq`与`FakeResp`类型，定义如下

| 属性      | 返回类型 | 作用                                                 |
| --------- | -------- | ---------------------------------------------------- |
| url       | str      |
| raw     | str      | 请求包完整头                                         |
| method    | str      |                                                      |
| suffix    | str      | url的文件后缀,例如 http://xxx.com/aa.php 将返回 .php |
| headers   | dict     |                                                      |
| hostname  | str      |                                                      |
| port      | int      |                                                      |
| cookies   | dict     |                                                      |
| params    | dict     |                                                      |
| post_hint | str      | post文件上传类型                                     |
| post_data | dict     |                                                      |
| data      | str      | 原始请求头
| netloc    | str      | url域名形如 http://xxx.com

### FakeResp 

| 属性      | 返回类型 | 作用                                                 |
| --------- | -------- | ---------------------------------------------------- |
| status_code       | int      | 返回状态码
| content     | byte      | 返回字节类型                                         |
| headers    | dict      | 返回请求头                                                     |
| raw    | str      | 返回包的http返回文本 |
| text   | str     |   返回文本                                                  |

## Result格式
w13scan的结果文件以json格式为主。
```json
{
    "name": "XSS语义化探测插件", // 插件名称
    "path": "/plugins/PerFile/xss.py", // 插件相对路径
    "url": "https://test.demo/xss.php?a=1", // 测试url
    "result": "XSS注入", // 输出结果
    "type": "xss", // 插件类型
    "createtime": "2020-04-11 11:21:23", // 创建时间
    "detail": {
      "payload探测":[ // key值为发包阶段的名称
        {
          "request": "", // 发送的请求包
          "response": "", // 返回的响应包
          "msg": "", // 这次发包的过程分析以及推测结果
          "basic": {
              "param": "", // 发包针对参数
              "value": "", // 发包参数的值
              "position": "" // 发包的位置，get，post 或cookie
          }
        }
      ]
    }
}
```

