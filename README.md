<h1 align="center">W13Scan</h1>

> W13scan 是基于Python3的一款开源的安全评估器,它支持主动扫描模式和被动扫描模式，也可以轻松集成在Burpsuite上，能运行在Windows、Linux、Mac上。

[![GitHub issues](https://img.shields.io/github/issues/boy-hack/w13scan)](https://github.com/boy-hack/w13scan/issues)  [![GitHub stars](https://img.shields.io/github/stars/boy-hack/w13scan)](https://github.com/boy-hack/w13scan/stargazers) [![GitHub forks](https://img.shields.io/github/forks/boy-hack/w13scan)](https://github.com/boy-hack/w13scan/network) [![GitHub license](https://img.shields.io/github/license/boy-hack/w13scan)](https://github.com/boy-hack/w13scan/blob/master/LICENSE)


## 声明
W13Scan仅提供给授权的渗透测试以及教育行为使用

## 特点
相比于其他专业的扫描工具，w13scan也有自己独有的优点。
### 免费/开源
安全从业人员可能不会信任任何程序，唯一能让人稍微信任的就是开源代码。

安全是建立在信任之上，信任需要开放和透明。w13scan核心代码完全开源，任何人可以检查其代码的安全性。

可以方便针对一些棘手且高度专业化的环境，可以按照w13scan开发文档补充其功能，自定义需要的模块。

### 丰富的检测插件
- [x] XSS扫描
    - 基于语义的反射型XSS扫描，准确率极高
- [x] jsonp信息泄漏
    - 基于语义解析寻找敏感信息
- [x] sql注入
    - 基于报错SQL注入检测
    - 基于网页相似度布尔类型的SQL注入检测
    - 基于时间的SQL注入检测
- [x] http smuggling 走私攻击
- [x] Fastjson检测与利用
- [x] .Net通杀Xss检测
    - portswigger 2019十大攻击技术第六名
- [x] iis解析漏洞
- [x] 敏感文件信息泄漏
    - 支持含备份文件，debug文件，js敏感信息,php真实路径泄漏,仓库泄漏，phpinfo泄漏，目录遍历等
- [x] baseline检测(反序列化参数检测)
- [x] 命令/代码注入检测
    - 支持asp,php等语言的检测
    - 支持系统命令注入检测(支持无回显检测)
    - 支持get,post,cookie等方式检测
- [x] 路径穿越漏洞
- [x] struts2漏洞检测
    - 包括s2-016、s2-032、s2-045漏洞
- [x] webpack打包源文件泄漏

### 扫描细节的处理
分享w13scan的一些扫描细节处理
- 支持扫描在 Get,Post,Cookie,Uri(伪静态) 上检测
- w13scan内置第三方`dnslog.cn`反连平台(默认开启)，也内置有自己的反连平台(默认不开启，需配置)，用于检测无回显漏洞。
- w13scan会记录发包过程及详情，并推荐可能的测试方案。
    - 有时候漏洞检测无法知道是否是漏扫插件的误报还是程序本身有问题，w13scan会详细说明扫描到的漏洞是怎么被发现的，以及一些判定过程。
- 在扫描过程中会进行简单的信息收集，如收集`网站框架`，`操作系统`，`编程语言`,`web中间件`等信息，后续的检测中会根据信息收集的程度构造payload，信息收集插件在`fingprints`目录。
- 扫描器会通过`html与js的语义化分析`自动从网页中寻找更多参数用于测试,以及根据wooyun漏洞库top参数合并，并根据算法只保留动态的参数进行测试。
- w13scan会实时将结果以json的格式写入到output目录下,开启`--html`后，会实时生成html格式的漏洞报告。
- level发包等级，从1~5，会发送越来越多的数据包
    - 1 发送简单的检测数据包
    - 2 无视指纹识别的环境进行插件扫描(部分插件需要指纹识别到环境才会进行扫描)
    - 3 带上cookie扫描
    - 4 对uri进行探测(分离url，可探测伪静态情况)
    - 5 针对所有情况发送请求包

## 使用

### 安装
### Help

### 简单的主动扫描

### 被动扫描
#### HTTPS支持
If you want w13scan to support https, similar to BurpSuite, first need to set up a proxy server (default 127.0.0.1:7778), then go to http://w13scan.ca to download the root certificate and trust it.

### 结合动态爬虫扫描
### 与Burpsuite结合扫描
### 开发
## Contributors
- [CONTRIBUTORS](CONTRIBUTORS.md)
