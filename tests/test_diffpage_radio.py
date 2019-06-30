#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/6/30 12:01 PM
# @Author  : w8ay
# @File    : test_diffpage_radio.py
import unittest

import requests

from lib.helper.diifpage import GetRatio, fuzzy_equal


class TestCase(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_diff_page_radio(self):
        url1 = "https://x.hacking8.com/post-348.html"
        url2 = "https://x.hacking8.com/post-342.html"
        html1 = requests.get(url1).text
        html2 = requests.get(url2).text
        radio = GetRatio(html1, html2)
        print(radio)

    def test_diff_page_radio_text(self):
        html1 = '''
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8" />
    <title>DoraBox - SQLi_STRING</title>
</head>
<body>
	<div class="tpl-content-wrapper">
            <div class="tpl-content-page-title">
                搜索
            </div>
            </br>
            <div class="tpl-portlet-components">
                <div class="portlet-title">
                    <div class="caption font-green bold">
                        <span class="am-icon-code"></span> &nbsp;&nbsp;
                    </div>
                    <div class="tpl-portlet-input tpl-fz-ml">
                    </div>
                </div>
                <div class="tpl-block">
                    <div class="am-g">

                <div class="am-u-sm-12">
                <div class="am-u-lg-3 am-u-md-6 am-u-sm-12 result-padding">
                    <div class="dashboard-stat blue">
                        <div class="visual">
                            <i class="am-icon-comments-o"></i>
                        </div>
                        <div class="details">
                            <div class="desc"> 域名资产记录 </div>
                        </div>
                        <a class="more" href="#"> 查看更多
                    <i class="m-icon-swapright m-icon-white"></i>
                </a>
                    </div>
                </div>
                <div class="am-u-lg-3 am-u-md-6 am-u-sm-12 result-padding">
                    <div class="dashboard-stat red">
                        <div class="visual">
                            <i class="am-icon-bar-chart-o"></i>
                        </div>
                        <div class="details">
                            <div class="desc"> IP总数 </div>
                        </div>
                        <a class="more" href="#"> 查看更多
                    <i class="m-icon-swapright m-icon-white"></i>
                </a>
                    </div>
                </div>
                <div class="am-u-lg-3 am-u-md-6 am-u-sm-12 result-padding">
                    <div class="dashboard-stat green">
                        <div class="visual">
                            <i class="am-icon-apple"></i>
                        </div>
                        <div class="details">
                            <div class="desc"> 端口服务资产 </div>
                        </div>
                        <a class="more" href="#"> 查看更多
                    <i class="m-icon-swapright m-icon-white"></i>
                </a>
                    </div>
                </div>
                <div class="am-u-lg-3 am-u-md-6 am-u-sm-12 result-padding">
                    <div class="dashboard-stat purple">
                        <div class="visual">
                            <i class="am-icon-android"></i>
                        </div>
                        <div class="details">
                            <div class="desc"> 漏洞总数 </div>
                        </div>
                        <a class="more" href="#"> 查看更多
                    <i class="m-icon-swapright m-icon-white"></i>
                </a>
                    </div>
                </div>
            </div>
            
                        <div class="am-u-sm-12">
                        	<form action='' method='GET'>title: <input type='text' name='title' id='form1'><input type='submit' name='submit' value='submit'></form><hr>SQLi语句：SELECT * FROM news WHERE title='<font color='red'>DoraBox</font>'<hr><center><table border='2'><tr><td>标题</td><td>内容</td></tr><tr><td></td><td></td></tr></table></center>                                <table lay-filter="demo">
                                    <thead>
                                        <tr>
                                        <th lay-data="{field:'id',sort:true}">
                                                    ID
                                                </th>
                                                <th lay-data="{field:'domain',sort:true,minWidth: 150}">
                                                    Domain
                                                </th>
                                                <th lay-data="{field:'ip',sort:true,minWidth: 150}">
                                                    Ip
                                                </th>
                                                <th lay-data="{field:'title',minWidth: 150}">
                                                    网页标题
                                                </th>
                                                <th lay-data="{field:'webstruct',minWidth: 150}">
                                                    网站组件
                                                </th>
                                                <th lay-data="{field:'port',minWidth: 150}">
                                                    端口服务
                                                </th>
                                                <th lay-data="{field:'index',hide:true}">
                                                    index
                                                </th>
                                                <th lay-data="{field:'rid',hide:true}">
                                                    rid
                                                </th>
                                                <th lay-data="{field:'other', width: 180}">
                                                    其他
                                                </th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                    
                                    </tbody>
                                </table>
                            </div>
                        </div>
                            <form class="am-form">
                                
                            
                                <hr>

                            </form>
                        </div>
                </div>
                <div class="tpl-alert"></div>
            </div>

        </div>
        <script>
;!function(){
$(".buttonstruct").click(function(){

    layer.open({
        type: 1,
        shade: false,
        title: false, //不显示标题
        content: $(this).next(".webstruct"), //捕获的元素，注意：最好该指定的元素要存放在body最外层，否则可能被其它的相对元素所影响
        cancel: function(){
            // layer.msg('捕获就是从页面已经存在的元素上，包裹layer的结构', {time: 5000, icon:6});
        }
    });
    
});

$(".scanresult").click(function(){

layer.open({
    type: 1,
    shade: false,
    title: false, //不显示标题
    content: $(this).next(".webscanresult"), //捕获的元素，注意：最好该指定的元素要存放在body最外层，否则可能被其它的相对元素所影响
    cancel: function(){
        // layer.msg('捕获就是从页面已经存在的元素上，包裹layer的结构', {time: 5000, icon:6});
    }
});

});

layui.use(['table', 'laytpl'],
        function() {
            var table = layui.table;
            var laytpl = layui.laytpl;

            //转换静态表格
            table.init('demo', {
                limit: 10000 //注意：请务必确保 limit 参数（默认：10）是与你服务端限定的数据条数一致
                //支持所有基础参数
            });

            table.on('tool(demo)',
            function(obj) {
                var data = obj.data;
                console.log(data.index,data.rid);
                var root = '
        '''
        html2 = '''
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8" />
    <title>DoraBox - SQLi_STRING</title>
</head>
<body>
	<div class="tpl-content-wrapper">
            <div class="tpl-content-page-title">
                搜索
            </div>
            </br>
            <div class="tpl-portlet-components">
                <div class="portlet-title">
                    <div class="caption font-green bold">
                        <span class="am-icon-code"></span> &nbsp;&nbsp;
                    </div>
                    <div class="tpl-portlet-input tpl-fz-ml">
                    </div>
                </div>
                <div class="tpl-block">
                    <div class="am-g">

                <div class="am-u-sm-12">
                <div class="am-u-lg-3 am-u-md-6 am-u-sm-12 result-padding">
                    <div class="dashboard-stat blue">
                        <div class="visual">
                            <i class="am-icon-comments-o"></i>
                        </div>
                        <div class="details">
                            <div class="desc"> 域名资产记录 </div>
                        </div>
                        <a class="more" href="#"> 查看更多
                    <i class="m-icon-swapright m-icon-white"></i>
                </a>
                    </div>
                </div>
                <div class="am-u-lg-3 am-u-md-6 am-u-sm-12 result-padding">
                    <div class="dashboard-stat red">
                        <div class="visual">
                            <i class="am-icon-bar-chart-o"></i>
                        </div>
                        <div class="details">
                            <div class="desc"> IP总数 </div>
                        </div>
                        <a class="more" href="#"> 查看更多
                    <i class="m-icon-swapright m-icon-white"></i>
                </a>
                    </div>
                </div>
                <div class="am-u-lg-3 am-u-md-6 am-u-sm-12 result-padding">
                    <div class="dashboard-stat green">
                        <div class="visual">
                            <i class="am-icon-apple"></i>
                        </div>
                        <div class="details">
                            <div class="desc"> 端口服务资产 </div>
                        </div>
                        <a class="more" href="#"> 查看更多
                    <i class="m-icon-swapright m-icon-white"></i>
                </a>
                    </div>
                </div>
                <div class="am-u-lg-3 am-u-md-6 am-u-sm-12 result-padding">
                    <div class="dashboard-stat purple">
                        <div class="visual">
                            <i class="am-icon-android"></i>
                        </div>
                        <div class="details">
                            <div class="desc"> 漏洞总数 </div>
                        </div>
                        <a class="more" href="#"> 查看更多
                    <i class="m-icon-swapright m-icon-white"></i>
                </a>
                    </div>
                </div>
            </div>
            
                        <div class="am-u-sm-12">
                        	<form action='' method='GET'>title: <input type='text' name='title' id='form1'><input type='submit' name='submit' value='submit'></form><hr>SQLi语句：SELECT * FROM news WHERE title='<font color='red'>a</font>'<hr><center><table border='2'><tr><td>标题</td><td>内容</td></tr><tr><td>a</td><td>MstLab are very cool.MstLab are very cool.MstLab are very cool.MstLab are very cool.MstLab are very cool.MstLab are very cool.MstLab are very cool.MstLab are very cool.MstLab are very cool.MstLab are very cool.MstLab are very cool.MstLab are very cool.MstLab are very cool.MstLab are very cool.MstLab are very cool.MstLab are very cool.MstLab are very cool.MstLab are very cool.MstLab are very cool.MstLab are very cool.MstLab are very cool.MstLab are very cool.MstLab are very cool.MstLab are very cool.MstLab are very cool.MstLab are very cool.MstLab are very cool.MstLab are very cool.MstLab are very cool.MstLab are very cool.MstLab are very cool.MstLab are very cool.MstLab are very cool.MstLab are very cool.MstLab are very cool.MstLab are very cool.MstLab are very cool.MstLab are very cool.MstLab are very cool.MstLab are very cool.MstLab are very cool.MstLab are very cool.MstLab are very cool.MstLab are very cool.MstLab are very cool.MstLab are very cool.MstLab are very cool.MstLab are very cool.MstLab are very cool.</td></tr></table></center>                                <table lay-filter="demo">
                                    <thead>
                                        <tr>
                                        <th lay-data="{field:'id',sort:true}">
                                                    ID
                                                </th>
                                                <th lay-data="{field:'domain',sort:true,minWidth: 150}">
                                                    Domain
                                                </th>
                                                <th lay-data="{field:'ip',sort:true,minWidth: 150}">
                                                    Ip
                                                </th>
                                                <th lay-data="{field:'title',minWidth: 150}">
                                                    网页标题
                                                </th>
                                                <th lay-data="{field:'webstruct',minWidth: 150}">
                                                    网站组件
                                                </th>
                                                <th lay-data="{field:'port',minWidth: 150}">
                                                    端口服务
                                                </th>
                                                <th lay-data="{field:'index',hide:true}">
                                                    index
                                                </th>
                                                <th lay-data="{field:'rid',hide:true}">
                                                    rid
                                                </th>
                                                <th lay-data="{field:'other', width: 180}">
                                                    其他
                                                </th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                    
                                    </tbody>
                                </table>
                            </div>
                        </div>
                            <form class="am-form">
                                
                            
                                <hr>

                            </form>
                        </div>
                </div>
                <div class="tpl-alert"></div>
            </div>

        </div>
        <script>
;!function(){
$(".buttonstruct").click(function(){

    layer.open({
        type: 1,
        shade: false,
        title: false, //不显示标题
        content: $(this).next(".webstruct"), //捕获的元素，注意：最好该指定的元素要存放在body最外层，否则可能被其它的相对元素所影响
        cancel: function(){
            // layer.msg('捕获就是从页面已经存在的元素上，包裹layer的结构', {time: 5000, icon:6});
        }
    });
    
});

$(".scanresult").click(function(){

layer.open({
    type: 1,
    shade: false,
    title: false, //不显示标题
    content: $(this).next(".webscanresult"), //捕获的元素，注意：最好该指定的元素要存放在body最外层，否则可能被其它的相对元素所影响
    cancel: function(){
        // layer.msg('捕获就是从页面已经存在的元素上，包裹layer的结构', {time: 5000, icon:6});
    }
});

});

layui.use(['table', 'laytpl'],
        function() {
            var table = layui.table;
            var laytpl = layui.laytpl;

            //转换静态表格
            table.init('demo', {
                limit: 10000 //注意：请务必确保 limit 参数（默认：10）是与你服务端限定的数据条数一致
                //支持所有基础参数
            });

            table.on('tool(demo)',
            function(obj) {
                var data = obj.data;
                console.log(data.index,data.rid);
                var root = '
        '''
        radio = GetRatio(html1, html2)
        print(radio)

    def test_fuzzy_equal(self):
        url1 = "http://emlog6.demo/?post=1"
        url2 = "http://emlog6.demo/?post=2"
        html1 = requests.get(url1).text
        html2 = requests.get(url2).text
        print(fuzzy_equal(html1, html2))
