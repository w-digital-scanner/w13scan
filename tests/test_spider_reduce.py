import unittest

from lib.spiderset import SpiderSet


class TestCase(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_reduce(self):
        urls = [
            "https://x.hacking8.com/post-348.html",
            "https://x.hacking8.com/post-342.html",
            "https://x.hacking8.com/?post=223",
            "https://x.hacking8.com/?post=22",
            "https://x.hacking8.com/?=post=1",
            "https://x.hacking8.com/?post=666",
            "https://x.hacking8.com/?post=66",
            "https://x.hacking8.com/?post=6&id=1",
        ]
        spider = SpiderSet()
        result = []
        for url in urls:
            ret = spider.add(url, 'TestPlugin')
            result.append(ret)
        self.assertTrue(result == [True, False, True, True, True, False, False, False])
