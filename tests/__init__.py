#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/6/29 6:01 PM
# @Author  : w8ay
# @File    : __init__.py
import sys
import time
import re

content = '''

<!DOCTYPE html>
<html><head><meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<meta charset="UTF-8">
<meta http-equiv="X-UA-Compatible" content="IE=11,IE=10,IE=9,IE=8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=0, minimum-scale=1.0, maximum-scale=1.0">
<meta name="apple-mobile-web-app-title" content="emlog大前端">
<meta name="keywords" content="信息安全,emlog大前端,小草窝" />
<meta name="description" content="博主是一名天朝的学生，喜欢折腾各种奇怪的语言，喜欢探索未知的事情" />
<meta name="generator" content="emlog大前端" />
<title>小草窝博客</title>
<link rel="shortcut icon" href="https://x.hacking8.com/content/templates/emlog_dux/favicon.ico">
<link href="https://x.hacking8.com/content/templates/emlog_dux/style/bootstrap.min.css" rel="stylesheet">
<link href="https://x.hacking8.com/content/templates/emlog_dux/style/font-awesome.min.css" rel="stylesheet">
<script src="https://x.hacking8.com/content/templates/emlog_dux/js/jquery.min.js"></script>
<link rel="stylesheet" id="da-main-css" href="https://x.hacking8.com/content/templates/emlog_dux/style/main.css?ver=4.5.1" type="text/css" media="all">
<link rel="stylesheet" href="https://x.hacking8.com/content/templates/emlog_dux/images/OwO/OwO.min.css" type="text/css">
<link rel="stylesheet" href="https://x.hacking8.com/content/templates/emlog_dux/style/prettify.css" type="text/css">
<!--[if lt IE 9]><script src="http://apps.bdimg.com/libs/html5shiv/r29/html5.min.js"></script><![endif]-->
<!-- <script language="javascript">if(top !== self){location.href = "about:blank";}</script> -->
<script src="//libs.baidu.com/bootstrap/3.0.3/js/bootstrap.min.js"></script>
<script src="https://x.hacking8.com/include/lib/js/common_tpl.js" type="text/javascript"></script>
<style type="text/css">
.logo a{
	background-image:url("https://x.hacking8.com/logo.png");
}
</style>
</head>
<body class="home blog ">
<div id="wrap">
<header class="header">
<div class="container">
	<h1 class="logo"><a href="https://x.hacking8.com/" title="">小草窝博客</a></h1>	<div class="brand">又一个</br>emlog大前端主题</div>
	<ul class="site-nav site-navbar">
				<li class="item current">
		
					<a href="https://x.hacking8.com/" > <i class='fa fa-home'></i> 首页</a>
			            		</li>
			<li class="item common">
		
					<a href="https://x.hacking8.com/sort/zhemo" > <i class='fa fa-bug'></i> 各类折腾</a>
			            		</li>
			<li class="item common">
		
					<a href="https://x.hacking8.com/sort/12" > <i class='fa fa-code'></i> 学习记录</a>
			            <ul class="sub-menu">
                <li><a href="https://x.hacking8.com/sort/8">python</a></li><li><a href="https://x.hacking8.com/sort/10">php</a></li><li><a href="https://x.hacking8.com/sort/11">C语言</a></li><li><a href="https://x.hacking8.com/sort/16">golang</a></li><li><a href="https://x.hacking8.com/sort/17">前端学习</a></li><li><a href="https://x.hacking8.com/sort/18">漏洞复现</a></li>			</ul>
                        		</li>
			<li class="item common">
		
					<a href="https://x.hacking8.com/sort/5" > <i class='fa fa-cube'></i> 网络安全</a>
			            		</li>
			<li class="navto-search"><a href="javascript:;" class="search-show active"><i class="fa fa-search"></i></a></li>
	</ul>
	<div class="topbar">
		<ul class="site-nav topmenu">
				<li>
	 <a href="https://github.com/boy-hack" target="_blank"><i class="fa fa-github" aria-hidden="true"></i>Github</a> 
</li>
<li>
	<a href="https://x.hacking8.com/me.html">关于我</a> 
</li>
<li>
	<a href="https://x.hacking8.com/comment.html">留言板</a> 
</li>
<li>
				<a href="">旗下网站 <i class="fa fa-angle-down"></i></a>
				<ul class="sub-menu">
					<li><a  rel="external nofollow" href="https://bugs.hacking8.com/tiquan/"> 提权辅助</a></li>
<li><a  rel="external nofollow" href="https://x.hacking8.com/java-runtime.html"> Java Runtime Exec</a></li>
				</ul>
			</li>
<li>
				<a href="">模式切换 <i class="fa fa-angle-down"></i></a>
				<ul class="sub-menu">
					<li><a  rel="external nofollow" href="https://x.hacking8.com/?blog"> 博客模式</a></li>
					<li><a  rel="external nofollow" href="https://x.hacking8.com/?gfs"> 高富帅模式</a></li>
					<li><a  rel="external nofollow" href="https://x.hacking8.com/?image"> 图片模式</a></li>
					<li><a  href="https://x.hacking8.com/?zazhi"> 杂志模式</a></li>
				</ul>
			</li>		</ul>
		
	</div>
	<i class="fa fa-bars m-icon-nav"></i>
</div>
</header>
<div class="site-search">
<div class="container">
	<form method="get" class="site-search-form" action="https://x.hacking8.com/index.php">
		<input class="search-input" name="keyword" type="text" placeholder="输入关键字搜索"><button class="search-btn" type="submit"><i class="fa fa-search"></i></button>
	</form>
</div>
</div>
<div class="pjax">
<section class="container">
	<div class="content-wrap">
	<div class="content">
		
	<article class="excerpt excerpt-multi">
		
	<header>	    <a class="cat" href="https://x.hacking8.com/sort/8">python</a>
	 <h2><a href="https://x.hacking8.com/post-348.html" title="Python多线程与协程对比.md">Python多线程与协程对比.md</a></h2></header><p class="meta"><time><i class="fa fa-clock-o"></i>2019-6-28</time><span class="pv"><i class="fa fa-eye"></i>阅读(18)</span><span class="pc"><i class="fa fa-comments-o"></i>评论(<span id="sourceId::6312" class="cy_cmt_count">0</span>)</span></p>
	<p class="focus"><a class="thumbnail" href="https://x.hacking8.com/post-348.html"><span class="item"><span class="thumb-span"><img class="thumb" src="" data-original="https://images.hacking8.com/2019/06/28/Q6M9u_image-20190621144751219.png"></span></span><span class="item"><span class="thumb-span"><img class="thumb" src="" data-original="https://images.hacking8.com/2019/06/28/kSIBt_image-20190621144546954.png"></span></span><span class="item"><span class="thumb-span"><img class="thumb" src="" data-original="https://images.hacking8.com/2019/06/28/IZQ6H_image-20190621145136659.png"></span></span><span class="item"><span class="thumb-span"><img class="thumb" src="" data-original="https://images.hacking8.com/2019/06/28/AxuWi_image-20190621150107622.png"></span></span><span class="item"><span class="thumb-span"><img class="thumb" src="" data-original="https://images.hacking8.com/2019/06/28/UbuFh_image-20190621151305461.png"></span></span><span class="item"><span class="thumb-span"><img class="thumb" src="" data-original="https://images.hacking8.com/2019/06/28/yGF4b_image-20190621153724104.png"></span></span><span class="item"><span class="thumb-span"><img class="thumb" src="" data-original="https://images.hacking8.com/2019/06/28/HcxX0_image-20190621152111696.png"></span></span><span class="item"><span class="thumb-span"><img class="thumb" src="" data-original="https://images.hacking8.com/2019/06/28/0cdz7_image-20190621152246995.png"></span></span></a></p>	<p class="note"></p></article>
	<article class="excerpt excerpt-2">
		<p class="focus"><a class="thumbnail" href="https://x.hacking8.com/post-347.html">
	<span class="item">
    
    <span class="thumb-span"><img class="thumb" src="https://x.hacking8.com/content/templates/emlog_dux/images/lazyload.gif" style="display: inline;" data-original="https://x.hacking8.com/content/templates/emlog_dux/images/random/7.jpg"></span>
    
    </span></a></p>
		
	<header>	    <a class="cat" href="https://x.hacking8.com/sort/5">网络安全</a>
	 <h2><a href="https://x.hacking8.com/post-347.html" title="w3af爬虫攻击规则.md">w3af爬虫攻击规则.md</a></h2></header><p class="meta"><time><i class="fa fa-clock-o"></i>2019-6-25</time><span class="pv"><i class="fa fa-eye"></i>阅读(64)</span><span class="pc"><i class="fa fa-comments-o"></i>评论(<span id="sourceId::6312" class="cy_cmt_count">2</span>)</span></p>
		<p class="note">前几天用了下长亭的xray扫描器，用代理扫描的功能，测试的内网环境的一些网站，效果还不错，也激发了我的灵感，我也要造一个被动扫描器的轮子！下面是整理的w3af的爬虫相关的插件功能，w3af的爬虫攻击分为两类，一类是基于爬虫获取更多地址，一类是一个具体地址进行的攻击。因为太多了，先把对应目录列出来，需要的时候在详细看。  
根据url生成对应的fuzz参数_...</p></article>
	<article class="excerpt excerpt-3">
		<p class="focus"><a class="thumbnail" href="https://x.hacking8.com/post-346.html">
	<span class="item">
    
    <span class="thumb-span"><img class="thumb" src="https://x.hacking8.com/content/templates/emlog_dux/images/lazyload.gif" style="display: inline;" data-original="https://x.hacking8.com/content/templates/emlog_dux/images/random/7.jpg"></span>
    
    </span></a></p>
		
	<header>	    <a class="cat" href="https://x.hacking8.com/sort/4">碎碎语</a>
	 <h2><a href="https://x.hacking8.com/post-346.html" title="下半年计划～">下半年计划～</a></h2></header><p class="meta"><time><i class="fa fa-clock-o"></i>2019-6-16</time><span class="pv"><i class="fa fa-eye"></i>阅读(171)</span><span class="pc"><i class="fa fa-comments-o"></i>评论(<span id="sourceId::6312" class="cy_cmt_count">4</span>)</span></p>
		<p class="note">在年初定了一个本年必完成四个计划，随着昨天六级考完，已经完成了三个了（zscan，w12scan,英语六级），剩下一个就是sqlmap的写书计划了～
在2018年总结的时候也制定了一些关于技术方面的checklist https://x.hacking8.com/post-316.html  完成可能还需要一段时间。但是已经到下半年了，单纯完成这些计划似乎...</p></article>
	<article class="excerpt excerpt-multi">
		
	<header>	    <a class="cat" href="https://x.hacking8.com/sort/8">python</a>
	 <h2><a href="https://x.hacking8.com/post-345.html" title="w3af 信息收集规则.md">w3af 信息收集规则.md</a></h2></header><p class="meta"><time><i class="fa fa-clock-o"></i>2019-6-13</time><span class="pv"><i class="fa fa-eye"></i>阅读(166)</span><span class="pc"><i class="fa fa-comments-o"></i>评论(<span id="sourceId::6312" class="cy_cmt_count">1</span>)</span></p>
	<p class="focus"><a class="thumbnail" href="https://x.hacking8.com/post-345.html"><span class="item"><span class="thumb-span"><img class="thumb" src="https://x.hacking8.com/content/templates/emlog_dux/images/lazyload.gif" data-original="https://images.hacking8.com/2019/06/13/gVHDt_image-20190613142412753.png"></span></span><span class="item"><span class="thumb-span"><img class="thumb" src="https://x.hacking8.com/content/templates/emlog_dux/images/lazyload.gif" data-original="https://images.hacking8.com/2019/06/13/Awsvd_image-20190613142607161.png"></span></span><span class="item"><span class="thumb-span"><img class="thumb" src="https://x.hacking8.com/content/templates/emlog_dux/images/lazyload.gif" data-original="https://images.hacking8.com/2019/06/13/LYEtZ_image-20190613142653176.png"></span></span><span class="item"><span class="thumb-span"><img class="thumb" src="https://x.hacking8.com/content/templates/emlog_dux/images/lazyload.gif" data-original="https://images.hacking8.com/2019/06/13/aH1qv_image-20190613143056010.png"></span></span></a></p>	<p class="note"></p></article>
	<article class="excerpt excerpt-5">
		<p class="focus"><a class="thumbnail" href="https://x.hacking8.com/post-344.html">
	<span class="item">
    
    <span class="thumb-span"><img class="thumb" src="https://x.hacking8.com/content/templates/emlog_dux/images/lazyload.gif" style="display: inline;" data-original="https://x.hacking8.com/content/templates/emlog_dux/images/random/5.jpg"></span>
    
    </span></a></p>
		
	<header>	    <a class="cat" href="https://x.hacking8.com/sort/15">新奇想法</a>
	 <h2><a href="https://x.hacking8.com/post-344.html" title="W13Scan 预告篇">W13Scan 预告篇</a></h2></header><p class="meta"><time><i class="fa fa-clock-o"></i>2019-6-4</time><span class="pv"><i class="fa fa-eye"></i>阅读(290)</span><span class="pc"><i class="fa fa-comments-o"></i>评论(<span id="sourceId::6312" class="cy_cmt_count">2</span>)</span></p>
		<p class="note">又来开坑啦～W12Scan只是一个资产管理的平台，它只会接收你提供的”URL”，那么，是不是应该做一款工具，来进行前期的URL收集以及poc批量扫描？或者，更厉害一点，常见的信息收集手段都可以集成到上面？
来点不一样同时，如果厌烦了命令行的操作，是不是可以来一款桌面版的？对，W13Scan构想是electron + Vue/React 来打造一款跨平台颜值...</p></article>
	<article class="excerpt excerpt-6">
		<p class="focus"><a class="thumbnail" href="https://x.hacking8.com/post-342.html">
	<span class="item">
    
    <span class="thumb-span"><img class="thumb" src="https://x.hacking8.com/content/templates/emlog_dux/images/lazyload.gif" style="display: inline;" data-original="https://images.hacking8.com/2019/05/16/TDHrt_w12scan.jpg"></span>
    
    </span></a></p>
		
	<header>	    <a class="cat" href="https://x.hacking8.com/sort/zhemo">各类折腾</a>
	 <h2><a href="https://x.hacking8.com/post-342.html" title="如何在本机搭建W12Scan.md">如何在本机搭建W12Scan.md</a></h2></header><p class="meta"><time><i class="fa fa-clock-o"></i>2019-5-16</time><span class="pv"><i class="fa fa-eye"></i>阅读(1243)</span><span class="pc"><i class="fa fa-comments-o"></i>评论(<span id="sourceId::6312" class="cy_cmt_count">3</span>)</span></p>
		<p class="note">W12Scan提供了用Docker一键部署的脚本，但是如果你是以学习的目的来看的话，本机搭建和调试变得重要许多，本文说说我自己本机调试环境是如何做的。
准备环境首先你需要明白W12Scan工作的整体流程图

W12Scan分为Web端与扫描(Client)端。
Web端代码开源https://github.com/w-digital-scanner/...</p></article>
	<article class="excerpt excerpt-7">
		<p class="focus"><a class="thumbnail" href="https://x.hacking8.com/post-341.html">
	<span class="item">
    
    <span class="thumb-span"><img class="thumb" src="https://x.hacking8.com/content/templates/emlog_dux/images/lazyload.gif" style="display: inline;" data-original="https://x.hacking8.com/content/templates/emlog_dux/images/random/7.jpg"></span>
    
    </span></a></p>
		
	<header>	    <a class="cat" href="https://x.hacking8.com/sort/4">碎碎语</a>
	 <h2><a href="https://x.hacking8.com/post-341.html" title="如何取舍用户的“友好”体验？">如何取舍用户的“友好”体验？</a></h2></header><p class="meta"><time><i class="fa fa-clock-o"></i>2019-5-8</time><span class="pv"><i class="fa fa-eye"></i>阅读(254)</span><span class="pc"><i class="fa fa-comments-o"></i>评论(<span id="sourceId::6312" class="cy_cmt_count">3</span>)</span></p>
		<p class="note">在V站看到这篇文章https://www.v2ex.com/t/561958 有感而发，也是记录自己的经历吧。
我将楼主的所有回复看完了，大概明白了楼主想法是想做一款“好用”的编译器/编程语言，具体如何好用主要体现，在语法上如何更加优雅。
我的经历我也有过类似的经历，之前我就想做一款“用户友好”的扫描器，因为之前用过的扫描器要么安装过于复杂，要么使用体验...</p></article>
	<article class="excerpt excerpt-8">
		<p class="focus"><a class="thumbnail" href="https://x.hacking8.com/post-340.html">
	<span class="item">
    
    <span class="thumb-span"><img class="thumb" src="https://x.hacking8.com/content/templates/emlog_dux/images/lazyload.gif" style="display: inline;" data-original="https://x.hacking8.com/content/templates/emlog_dux/images/random/4.jpg"></span>
    
    </span></a></p>
		
	<header>	    <a class="cat" href="https://x.hacking8.com/sort/zhemo">各类折腾</a>
	 <h2><a href="https://x.hacking8.com/post-340.html" title="如何构建一个网络空间搜索引擎-W12Scan-WEB篇.md">如何构建一个网络空间搜索引擎-W12Scan-WEB篇.md</a></h2></header><p class="meta"><time><i class="fa fa-clock-o"></i>2019-5-3</time><span class="pv"><i class="fa fa-eye"></i>阅读(1451)</span><span class="pc"><i class="fa fa-comments-o"></i>评论(<span id="sourceId::6312" class="cy_cmt_count">7</span>)</span></p>
		<p class="note">当黑客们不羁的灵魂受够了那些受到限制的空间搜索引擎，是否有想过使用自己搭建的网络空间搜索引擎呢？你只需要一台独立的服务器(配置取决于你想象的扫描速度，最低1G1H)即可拥有它，并且允许分布式搭建。搭建简单，使用简单，你还在等什么呢？趁着51的假期余温，简单写一篇说明文档。
说明这是W12Scan官方的安装搭建说明文档，将包含大部分w12scan使用过程中的...</p></article>
	<article class="excerpt excerpt-9">
		<p class="focus"><a class="thumbnail" href="https://x.hacking8.com/post-339.html">
	<span class="item">
    
    <span class="thumb-span"><img class="thumb" src="https://x.hacking8.com/content/templates/emlog_dux/images/lazyload.gif" style="display: inline;" data-original="https://x.hacking8.com/content/templates/emlog_dux/images/random/7.jpg"></span>
    
    </span></a></p>
		
	<header>	    <a class="cat" href="https://x.hacking8.com/sort/15">新奇想法</a>
	 <h2><a href="https://x.hacking8.com/post-339.html" title="安全圈大佬博客爬虫计划">安全圈大佬博客爬虫计划</a></h2></header><p class="meta"><time><i class="fa fa-clock-o"></i>2019-4-27</time><span class="pv"><i class="fa fa-eye"></i>阅读(595)</span><span class="pc"><i class="fa fa-comments-o"></i>评论(<span id="sourceId::6312" class="cy_cmt_count">2</span>)</span></p>
		<p class="note">看到Freebuf上那篇吃鸡分析的文章，数据分析还是强啊。很早的时候我就有QQ空间爬虫生成关系图的想法了，也实践写好了程序，如果多加些大佬，说不定可以直接从QQ空间爬虫，但是我加的人比较少，而且很多是自己的朋友，再加上深层次爬虫的时候很多大佬的QQ空间是关闭的，所以就不选择这个了。
博客爬虫从另一个角度出发，从大佬们的博客入手。简述一下我的思路。
1. ...</p></article>
	<article class="excerpt excerpt-multi">
		
	<header>	    <a class="cat" href="https://x.hacking8.com/sort/5">网络安全</a>
	 <h2><a href="https://x.hacking8.com/post-338.html" title="AntSword一个RCE.md">AntSword一个RCE.md</a></h2></header><p class="meta"><time><i class="fa fa-clock-o"></i>2019-4-20</time><span class="pv"><i class="fa fa-eye"></i>阅读(410)</span><span class="pc"><i class="fa fa-comments-o"></i>评论(<span id="sourceId::6312" class="cy_cmt_count">0</span>)</span></p>
	<p class="focus"><a class="thumbnail" href="https://x.hacking8.com/post-338.html"><span class="item"><span class="thumb-span"><img class="thumb" src="https://x.hacking8.com/content/templates/emlog_dux/images/lazyload.gif" data-original="https://images.hacking8.com/2019/04/20/8oLiB_image-20190420212213806.png"></span></span><span class="item"><span class="thumb-span"><img class="thumb" src="https://x.hacking8.com/content/templates/emlog_dux/images/lazyload.gif" data-original="https://images.hacking8.com/2019/04/20/YpDQc_image-20190420212308905.png"></span></span><span class="item"><span class="thumb-span"><img class="thumb" src="https://x.hacking8.com/content/templates/emlog_dux/images/lazyload.gif" data-original="https://images.hacking8.com/2019/04/20/e0xUh_antsword.gif"></span></span><span class="item"><span class="thumb-span"><img class="thumb" src="https://x.hacking8.com/content/templates/emlog_dux/images/lazyload.gif" data-original="https://images.hacking8.com/2019/04/20/0N8lF_image-20190420213845993.png"></span></span></a></p>	<p class="note"></p></article>

<div class="pagenavi"><ul>
 <span class='page now-page'>1</span>  <a href="https://x.hacking8.com/page/2">2</a>  <a href="https://x.hacking8.com/page/3">3</a>  <a href="https://x.hacking8.com/page/2" class='nextpages'>››</a>  <a href="https://x.hacking8.com/page/26" title="尾页">尾页</a></ul>
</div>

</div></div>
<div class="sidebar">



	
	<div class="widget widget_ui_textads widget_twitter"><a class="style01"><strong>最新微语</strong>
		<br><br><font size="2" color="#999">	
	一个手滑的操作删掉了”关于我“中的”我的项目“，现在也没有精力总结了，就让它逝去吧～	</font><br><br>
	<font color="#999">2019-06-03 21:27</font>
		</a>
	</div>
	<div class="widget widget_ui_comments"><span class="icon"><i class="fa fa-fire"></i></span><h3>热门文章</h3><ul>
		 	
	<li><a href="https://x.hacking8.com/post-344.html" title="W13Scan 预告篇"><img class="avatar avatar-50 photo avatar-default" height="50" width="50" src="https://x.hacking8.com/content/templates/emlog_dux/images/lazyload.gif" style="display: block;" data-original="https://x.hacking8.com/content/templates/emlog_dux/images/random/8.jpg"/> <strong>W13Scan 预告篇</strong>  <br /> <span> 290 次阅读  ,  2 则评论</span></a></li>
	 	
	<li><a href="https://x.hacking8.com/post-346.html" title="下半年计划～"><img class="avatar avatar-50 photo avatar-default" height="50" width="50" src="https://x.hacking8.com/content/templates/emlog_dux/images/lazyload.gif" style="display: block;" data-original="https://x.hacking8.com/content/templates/emlog_dux/images/random/4.jpg"/> <strong>下半年计划～</strong>  <br /> <span> 171 次阅读  ,  4 则评论</span></a></li>
	 	
	<li><a href="https://x.hacking8.com/post-345.html" title="w3af 信息收集规则.md"><img class="avatar avatar-50 photo avatar-default" height="50" width="50" src="https://x.hacking8.com/content/templates/emlog_dux/images/lazyload.gif" style="display: block;" data-original="https://images.hacking8.com/2019/06/13/gVHDt_image-20190613142412753.png"/> <strong>w3af 信息收集规则.md</strong>  <br /> <span> 166 次阅读  ,  1 则评论</span></a></li>
	 	
	<li><a href="https://x.hacking8.com/post-347.html" title="w3af爬虫攻击规则.md"><img class="avatar avatar-50 photo avatar-default" height="50" width="50" src="https://x.hacking8.com/content/templates/emlog_dux/images/lazyload.gif" style="display: block;" data-original="https://x.hacking8.com/content/templates/emlog_dux/images/random/2.jpg"/> <strong>w3af爬虫攻击规则.md</strong>  <br /> <span> 64 次阅读  ,  2 则评论</span></a></li>
	 	
	<li><a href="https://x.hacking8.com/post-348.html" title="Python多线程与协程对比.md"><img class="avatar avatar-50 photo avatar-default" height="50" width="50" src="https://x.hacking8.com/content/templates/emlog_dux/images/lazyload.gif" style="display: block;" data-original="https://images.hacking8.com/2019/06/28/Q6M9u_image-20190621144751219.png"/> <strong>Python多线程与协程对比.md</strong>  <br /> <span> 18 次阅读  ,  0 则评论</span></a></li>
	</ul></div>
	<div class="widget widget_ui_sort"><span class="icon"><i class="fa fa-hand-o-right"></i></span><h3 class="widget-title">分类</h3><div class="items"> <ul id="blogsort"> 

			<li> <a title="19 篇文章" href="https://x.hacking8.com/sort/2"><i class="fa fa-windows"></i> emlog</a> </li> 
			<li> <a title="73 篇文章" href="https://x.hacking8.com/sort/zhemo"><i class="fa fa-bug"></i> 各类折腾</a> </li> 
			<li> <a title="43 篇文章" href="https://x.hacking8.com/sort/4"><i class="fa fa-code"></i> 碎碎语</a> </li> 
			<li> <a title="19 篇文章" href="https://x.hacking8.com/sort/5"><i class="fa fa-bug"></i> 网络安全</a> </li> 
			<li> <a title="7 篇文章" href="https://x.hacking8.com/sort/15"><i class="fa fa-cube"></i> 新奇想法</a> </li> 
			<li> <a title="22 篇文章" href="https://x.hacking8.com/sort/12"><i class="fa fa-rocket"></i> 学习记录</a> </li> 
			<li> <a title="2 篇文章" href="https://x.hacking8.com/sort/13"><i class="fa fa-windows"></i> 上课笔记</a> </li> 
		</ul> </div> </div>
<div class="widget widget_ui_comments"> <span class="icon"><i class="fa fa-pencil-square-o"></i></span><h3> 最新评论</h3> <ul> 
		<li><a href="https://x.hacking8.com/post-41.html#2677" title="Emlog大前端4.0 文章页侧边栏设置 上的评论"><img class="avatar avatar-50 photo avatar-default" height="50" width="50" src="//q.qlogo.cn/headimg_dl?bs=qq&amp;dst_uin=448596350&amp;src_uin=qq.feixue.me&amp;fid=blog&amp;spec=100" style="display: block;" /> <strong>运营兔</strong> 1天前 说<br />我用的是4.9大前端和emlog6.0....</a></li>
		<li><a href="https://x.hacking8.com/post-347.html#2674" title="w3af爬虫攻击规则.md 上的评论"><img class="avatar avatar-50 photo avatar-default" height="50" width="50" src="//secure.gravatar.com/avatar/e1c276d127a76878bbe7a74f14e339f4?s=50&d=wavatar&r=g" style="display: block;" /> <strong>一鑫创研</strong> 3天前 说<br />整理的很详细，博主这几年发展的很不错，基...</a></li>
		<li><a href="https://x.hacking8.com/post-346.html#2673" title="下半年计划～ 上的评论"><img class="avatar avatar-50 photo avatar-default" height="50" width="50" src="//q.qlogo.cn/headimg_dl?bs=qq&amp;dst_uin=774740085&amp;src_uin=qq.feixue.me&amp;fid=blog&amp;spec=100" style="display: block;" /> <strong>AE博客</strong> 4天前 说<br />@小草：要啥灵感直接更新</a></li>
		<li><a href="https://x.hacking8.com/comment.html#2671" title="留言板 上的评论"><img class="avatar avatar-50 photo avatar-default" height="50" width="50" src="//secure.gravatar.com/avatar/e1c276d127a76878bbe7a74f14e339f4?s=50&d=wavatar&r=g" style="display: block;" /> <strong>一鑫创研技术</strong> 4天前 说<br />博主暑假要出去旅游吗？</a></li>
		<li><a href="https://x.hacking8.com/post-346.html#2670" title="下半年计划～ 上的评论"><img class="avatar avatar-50 photo avatar-default" height="50" width="50" src="//q.qlogo.cn/headimg_dl?bs=qq&amp;dst_uin=774740085&amp;src_uin=qq.feixue.me&amp;fid=blog&amp;spec=100" style="display: block;" /> <strong>AE博客</strong> 5天前 说<br />你得更新大前端！！！！！</a></li>
		<li><a href="https://x.hacking8.com/post-345.html#2669" title="w3af 信息收集规则.md 上的评论"><img class="avatar avatar-50 photo avatar-default" height="50" width="50" src="//secure.gravatar.com/avatar/e1c276d127a76878bbe7a74f14e339f4?s=50&d=wavatar&r=g" style="display: block;" /> <strong>一鑫创研</strong> 5天前 说<br />很不错，可以推荐给朋友看一下。</a></li>
	</ul> </div>
	<div class="widget widget_ui_tags"><span class="icon"><i class="fa fa-tags"></i></span><h3>标签云</h3><div class="items">
		<a href="https://x.hacking8.com/tag/%E5%AD%A6%E4%B9%A0%E8%AE%B0%E5%BD%95">学习记录 (9)</a>
		<a href="https://x.hacking8.com/tag/emlog%E5%A4%A7%E5%89%8D%E7%AB%AF%E6%94%B6%E8%B4%B9%E7%89%88">emlog大前端收费版 (9)</a>
		<a href="https://x.hacking8.com/tag/%E4%BB%A3%E7%A0%81%E5%AE%A1%E8%AE%A1">代码审计 (2)</a>
		<a href="https://x.hacking8.com/tag/markdown">markdown (4)</a>
		<a href="https://x.hacking8.com/tag/%E5%B0%8F%E8%8D%89%E6%92%AD%E6%94%BE%E5%99%A8">小草播放器 (3)</a>
		<a href="https://x.hacking8.com/tag/emlog%E5%A4%A7%E5%89%8D%E7%AB%AFF">emlog大前端F (7)</a>
		<a href="https://x.hacking8.com/tag/w8scan">w8scan (10)</a>
		<a href="https://x.hacking8.com/tag/sqlmap%E6%BA%90%E7%A0%81%E8%A7%A3%E6%9E%90">sqlmap源码解析 (14)</a>
		<a href="https://x.hacking8.com/tag/%E7%99%BD%E5%B8%BD%E5%AD%90%E5%B0%86web%E5%AE%89%E5%85%A8">白帽子将web安全 (1)</a>
		<a href="https://x.hacking8.com/tag/CMS%E5%9C%A8%E7%BA%BF%E8%AF%86%E5%88%AB">CMS在线识别 (3)</a>
		<a href="https://x.hacking8.com/tag/w9scan">w9scan (8)</a>
		<a href="https://x.hacking8.com/tag/%E5%9F%BA%E4%BA%8E%E6%B7%B1%E5%BA%A6%E5%AD%A6%E4%B9%A0%E7%9A%84CMS%E8%AF%86%E5%88%AB">基于深度学习的CMS识别 (3)</a>
		<a href="https://x.hacking8.com/tag/w10scan">w10scan (2)</a>
		<a href="https://x.hacking8.com/tag/oepngl%E4%BB%BFminecraft">oepngl仿minecraft (3)</a>
		<a href="https://x.hacking8.com/tag/w11scan">w11scan (4)</a>
		<a href="https://x.hacking8.com/tag/airpoc">airpoc (2)</a>
		<a href="https://x.hacking8.com/tag/w12scan">w12scan (12)</a>
		<a href="https://x.hacking8.com/tag/hack-requests">hack-requests (3)</a>
		<a href="https://x.hacking8.com/tag/requests">requests (1)</a>
		<a href="https://x.hacking8.com/tag/aireye">aireye (1)</a>
		<a href="https://x.hacking8.com/tag/docker">docker (1)</a>
		<a href="https://x.hacking8.com/tag/sqlmap%E7%9A%84%E6%8A%80%E6%9C%AF%E7%BB%86%E8%8A%82">sqlmap的技术细节 (5)</a>
		<a href="https://x.hacking8.com/tag/goWhatweb">goWhatweb (1)</a>
		<a href="https://x.hacking8.com/tag/REACT%E5%AD%A6%E4%B9%A0">REACT学习 (2)</a>
		<a href="https://x.hacking8.com/tag/w13scan">w13scan (1)</a>
		<a href="https://x.hacking8.com/tag/w3af">w3af (2)</a>
		</div>
	</div>
	<div class="widget widget_links flag_img"><span class="icon"><i class="fa fa-link"></i></span> <h3> 友情链接</h3><ul>
		<li>
	<a href="http://www.wwc-blog.com/" title="专注电脑，网络等技术分享,分享生活的点点滴滴！" target="_blank"> 网虫小王</a></li>  
		<li>
	<a href="http://www.70xk.com/" title="专注分享绿色优质精品软件" target="_blank"> 七零星空′s Blog</a></li>  
		<li>
	<a href="http://cxryun.cn/" title="点燃一颗香烟的时间，便是我一生的时光。陈小儒云（www.cxryun.cn）陈小儒的个人原创独立博客。" target="_blank"> 陈小儒云</a></li>  
		<li>
	<a href="http://www.mosq.cn/" title="森七博客(mosq.cn)是一个乐享网络资源的博客" target="_blank"> 森七博客</a></li>  
		<li>
	<a href="http://www.hackv.cn" title="专注网络资源|程序源码|免费空间|工具软件等分享" target="_blank"> 古韵博客</a></li>  
		<li>
	<a href="http://www.lengbaikai.net" title="现活跃于乌云、补天、漏洞盒子等互联网漏洞报告平台以及各大SRC安全应急响应中心单萌白帽狗一只，欢迎大牛交流技术，。" target="_blank"> 冷白开's Blog</a></li>  
		<li>
	<a href="http://pjax.cn/" title="欢迎来到Finally博客,这里有emlog主题模板、纯净系统、建站教程,博主QQ1501700017" target="_blank"> Finally</a></li>  
		<li>
	<a href="https://www.ercc.cc" title="如你所见什么都没有，甚至都没有一个人" target="_blank"> 无人小站</a></li>  
		<li>
	<a href="http://me.tongleer.com/" title="不老阁,Android开发,生活经验" target="_blank"> 不老阁</a></li>  
		<li>
	<a href="https://www.52ecy.cn/" title="干杯~'blog - 一个充满二次元风味的技术博客" target="_blank"> 阿珏博客</a></li>  
		<li>
	<a href="http://foreversong.cn/" title="信息安全博客,渗透测试,python,ctf,Docker,代码审计" target="_blank"> ADog's blog</a></li>  
		<li>
	<a href="https://blog.dyboy.cn/" title="本博客记录自己在学习路上的有趣的内容，比如web安全和程序开发，欢迎各位关注DYBOY的技术博客，一起学习进步！" target="_blank"> DYBOY's Blog</a></li>  
		<li>
	<a href="https://drops.org.cn/" title="dr0op Pentest Code-Audit Domain-Safe Hack-Tools" target="_blank"> dr0op@K4l0nG</a></li>  
		<li>
	<a href="https://www.cnblogs.com/ECJTUACM-873284962/" title="我很弱，但是我要坚强！绝不让那些为我付出过的人失望！" target="_blank"> Angel_Kitty</a></li>  
		<li>
	<a href="https://b1ue.cn/" title="浅蓝的个人博客" target="_blank"> 浅蓝 's blog</a></li>  
		<li>
	<a href="https://saucer-man.com/" title="网络安全" target="_blank"> saucerman</a></li>  
	</ul>
 </div>


<div class="widget widget_tit">
<span class="icon"><i class="fa fa-bar-chart"></i></span>
	<h3>站点统计</h3>
    <ul>
        <li><a><i class="fa fa-file-o"></i> 文章总数：260篇</a></li>
    <li><a> <i class="fa fa-twitch" aria-hidden="true"></i> 微语总数：100条</a></li>
    <li><a><i class="fa fa-comments-o" aria-hidden="true"></i> 评论总数：2407条</a></li>
	
	<li><a><i class="fa fa-bicycle" aria-hidden="true"></i> 运行天数: 1428天</a></li>
    </ul>
</div>
</div>

</section>
<footer class="footer">
<div class="container">
	<!--
		希望各位站长保留版权 您的支持就是我们最大的动力
		小草窝 Blog:http://blog.hacking8.com/
	-->
	
		<a href="http://www.miibeian.gov.cn" target="_blank">鄂ICP备18025574号</a>	
	<a href="https://x.hacking8.com/rss.php">RSS订阅</a>
<script>
var _hmt = _hmt || [];
(function() {
  var hm = document.createElement("script");
  hm.src = "https://hm.baidu.com/hm.js?15ff8e5e1c4320ac946c0504e10dda45";
  var s = document.getElementsByTagName("script")[0]; 
  s.parentNode.insertBefore(hm, s);
})();
</script>	</p>
	<p>Powered by <a href="http://www.emlog.net" title="骄傲的采用emlog系统">emlog</a> 
	©  Emlog大前端 theme By <span id="copyright"><a href="https://x.hacking8.com/" >小草窝</a></span><a href="https://x.hacking8.com/content/templates/emlog_dux/SiteMap.php" target="_blank"> SiteMap</a></p>
	<p>
</div>
</footer>
</div>
<div class="pjax_loading"></div>
<div class="pjax_loading1"></div>
</div>
</body>


<script>
window.jsui={
	www: 'https://x.hacking8.com/',
	uri: 'https://x.hacking8.com/content/templates/emlog_dux/',
	ver: '4.9',
	logocode: 'n',
	is_fix:'1',
	is_pjax:'',
	iasnum:'0',
	lazyload:'1',
	ajaxclient:'0'
};
</script>

<script type='text/javascript' src='https://x.hacking8.com/content/templates/emlog_dux/js/loader.js?ver=4.9.0' data-no-instant></script>
</html>
'''

match = re.findall(r'''(href|src)=["'](.*?)["']''', content, re.S | re.I)

print(match)