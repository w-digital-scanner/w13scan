#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time    : 2019/6/30 11:57 AM
# @Author  : w8ay
# @File    : diifpage.py
import re
from difflib import SequenceMatcher
from functools import reduce

from six import unichr


def getFilteredPageContent(page, onlyText=True, split=" "):
    """
    Returns filtered page content without script, style and/or comments
    or all HTML tags
    >>> getFilteredPageContent(u'<html><title>foobar</title><body>test</body></html>')
    u'foobar test'
    """

    retVal = page

    # only if the page's charset has been successfully identified
    retVal = re.sub(
        r"(?si)<script.+?</script>|<!--.+?-->|<style.+?</style>%s" % (r"|<[^>]+>|\t|\n|\r" if onlyText else ""),
        split, page)
    while retVal.find(2 * split) != -1:
        retVal = retVal.replace(2 * split, split)
    retVal = htmlunescape(retVal.strip().strip(split))

    return retVal


def getPageWordSet(page):
    """
    Returns word set used in page content
    >>> sorted(getPageWordSet(u'<html><title>foobar</title><body>test</body></html>'))
    [u'foobar', u'test']
    """

    retVal = set()

    # only if the page's charset has been successfully identified
    _ = getFilteredPageContent(page)
    retVal = set(re.findall(r"\w+", _))

    return retVal


def htmlunescape(value):
    """
    Returns (basic conversion) HTML unescaped value
    >>> htmlunescape('a&lt;b')
    'a<b'
    """

    retVal = value
    codes = (('&lt;', '<'), ('&gt;', '>'), ('&quot;', '"'), ('&nbsp;', ' '), ('&amp;', '&'))
    retVal = reduce(lambda x, y: x.replace(y[0], y[1]), codes, retVal)
    try:
        retVal = re.sub(r"&#x([^ ;]+);", lambda match: unichr(int(match.group(1), 16)), retVal)
    except ValueError:
        pass
    return retVal


def GetRatio(firstPage, secondPage):
    """
    Prints words appearing in two different response pages
    对比文本相似度，会去掉html标签
    """
    firstPage = getFilteredPageContent(firstPage)
    secondPage = getFilteredPageContent(secondPage)

    match = SequenceMatcher(None, firstPage, secondPage).ratio()
    return match


def split_by_sep(seq):
    """
    This method will split the HTTP response body by various separators,
    such as new lines, tabs, <, double and single quotes.

    This method is very important for the precision we get in chunked_diff!

    If you're interested in a little bit of history take a look at the git log
    for this file and you'll see that at the beginning this method was splitting
    the input in chunks of equal length (32 bytes). This was a good initial
    approach but after a couple of tests it was obvious that when a difference
    (something that was in A but not B) was found the SequenceMatcher got
    desynchronized and the rest of the A and B strings were also shown as
    different, even though they were the same but "shifted" by a couple of
    bytes (the size length of the initial difference).

    After detecting this I changed the algorithm to separate the input strings
    to this one, which takes advantage of the HTML format which is usually
    split by lines and organized by tabs:
        * \n
        * \r
        * \t

    And also uses tags and attributes:
        * <
        * '
        * "

    The single and double quotes will serve as separators for other HTTP
    response content types such as JSON.

    Splitting by <space> was an option, but I believe it would create multiple
    chunks without much meaning and reduce the performance improvement we
    have achieved.

    :param seq: A string
    :return: A list of strings (chunks) for the input string
    """
    chunks = []
    chunk = ''

    for c in seq:
        if c in '\n\t\r"\'<':
            chunks.append(chunk)
            chunk = ''
        else:
            chunk += c

    chunks.append(chunk)

    return chunks


def relative_distance_boolean(a_str, b_str, threshold=0.6):
    """
    Indicates if the strings to compare are similar enough. This (optimized)
    function is equivalent to the expression:
        relative_distance(x, y) > threshold

    :param a_str: A string object
    :param b_str: A string object
    :param threshold: Float value indicating the expected "similarity". Must be
                      0 <= threshold <= 1.0
    :return: A boolean value
    """
    if threshold == 0:
        return True
    elif threshold == 1.0:
        return a_str == b_str

    # First we need b_str to be the longer of both
    if len(b_str) < len(a_str):
        a_str, b_str = b_str, a_str

    alen = len(a_str)
    blen = len(b_str)

    if blen == 0 or alen == 0:
        return alen == blen

    if blen == alen and a_str == b_str and threshold <= 1.0:
        return True

    if threshold > upper_bound_similarity(a_str, b_str):
        return False
    else:
        # Bad, we can't optimize anything here
        simalar = SequenceMatcher(None,
                                  split_by_sep(a_str),
                                  split_by_sep(b_str)).quick_ratio()
        # print(simalar)
        return threshold <= simalar


def upper_bound_similarity(a, b):
    return (2.0 * len(a)) / (len(a) + len(b))


def fuzzy_equal(a_str, b_str, threshold=0.6):
    # type: (object, object, object) -> object
    """
    Indicates if the 'similarity' index between strings
    is *greater equal* than 'threshold'. See 'relative_distance_boolean'.
    """
    return relative_distance_boolean(a_str, b_str, threshold)


def findDynamicContent(firstPage, secondPage):
    """
    This function checks if the provided pages have dynamic content. If they
    are dynamic, proper markings will be made

    >>> findDynamicContent("Lorem ipsum dolor sit amet, congue tation referrentur ei sed. Ne nec legimus habemus recusabo, natum reque et per. Facer tritani reprehendunt eos id, modus constituam est te. Usu sumo indoctum ad, pri paulo molestiae complectitur no.", "Lorem ipsum dolor sit amet, congue tation referrentur ei sed. Ne nec legimus habemus recusabo, natum reque et per. <script src='ads.js'></script>Facer tritani reprehendunt eos id, modus constituam est te. Usu sumo indoctum ad, pri paulo molestiae complectitur no.")
    >>> kb.dynamicMarkings
    [('natum reque et per. ', 'Facer tritani repreh')]
    """

    if not firstPage or not secondPage:
        return

    blocks = list(SequenceMatcher(None, firstPage, secondPage).get_matching_blocks())
    dynamicMarkings = []

    # Removing too small matching blocks
    DYNAMICITY_BOUNDARY_LENGTH = 20
    for block in blocks[:]:
        (_, _, length) = block

        if length <= 2 * DYNAMICITY_BOUNDARY_LENGTH:
            blocks.remove(block)

    # Making of dynamic markings based on prefix/suffix principle
    if len(blocks) > 0:
        blocks.insert(0, None)
        blocks.append(None)

        for i in range(len(blocks) - 1):
            prefix = firstPage[blocks[i][0]:blocks[i][0] + blocks[i][2]] if blocks[i] else None
            suffix = firstPage[blocks[i + 1][0]:blocks[i + 1][0] + blocks[i + 1][2]] if blocks[i + 1] else None

            if prefix is None and blocks[i + 1][0] == 0:
                continue

            if suffix is None and (blocks[i][0] + blocks[i][2] >= len(firstPage)):
                continue

            if prefix and suffix:
                prefix = prefix[-DYNAMICITY_BOUNDARY_LENGTH:]
                suffix = suffix[:DYNAMICITY_BOUNDARY_LENGTH]

                for _ in (firstPage, secondPage):
                    match = re.search(r"(?s)%s(.+)%s" % (re.escape(prefix), re.escape(suffix)), _)
                    if match:
                        infix = match.group(1)
                        if infix[0].isalnum():
                            prefix = trimAlphaNum(prefix)
                        if infix[-1].isalnum():
                            suffix = trimAlphaNum(suffix)
                        break

            dynamicMarkings.append((prefix if prefix else None, suffix if suffix else None))

    return []


def removeDynamicContent(page, dynamicMarkings):
    """
    Removing dynamic content from supplied page basing removal on
    precalculated dynamic markings
    """

    if page:
        for item in dynamicMarkings:
            prefix, suffix = item

            if prefix is None and suffix is None:
                continue
            elif prefix is None:
                page = re.sub(r"(?s)^.+%s" % re.escape(suffix), suffix.replace('\\', r'\\'), page)
            elif suffix is None:
                page = re.sub(r"(?s)%s.+$" % re.escape(prefix), prefix.replace('\\', r'\\'), page)
            else:
                page = re.sub(r"(?s)%s.+%s" % (re.escape(prefix), re.escape(suffix)),
                              "%s%s" % (prefix.replace('\\', r'\\'), suffix.replace('\\', r'\\')), page)

    return page


def trimAlphaNum(value):
    """
    Trims alpha numeric characters from start and ending of a given value

    >>> trimAlphaNum('AND 1>(2+3)-- foobar')
    ' 1>(2+3)-- '
    """

    while value and value[-1].isalnum():
        value = value[:-1]

    while value and value[0].isalnum():
        value = value[1:]

    return value
