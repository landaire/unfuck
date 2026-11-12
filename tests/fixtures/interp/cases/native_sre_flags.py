# -*- coding: utf-8 -*-
import re

def info(m):
    if m is None:
        return None
    return (m.group(), m.groups(), m.span())

RESULT = [
    info(re.match(r'hello', 'HeLLo', re.I)), info(re.match(r'[a-c]+', 'AbC', re.I)), info(re.match(r'[^a]', 'A', re.I)),
    info(re.match(r'(a)\1', 'aA', re.I)), info(re.search(r'^b', 'a\nb', re.M)), info(re.search(r'a$', 'a\nb', re.M)),
    info(re.search(r'a.b', 'a\nb', re.S)), info(re.search(r'a.b', 'a\nb')), info(re.match(r'''
        (\d+)   # digits
        \s* , \s*
        (\d+)   # more digits
        ''', '12 , 34', re.X)),
    info(re.match(r'\w+', u'caf\xe9!', re.U)), info(re.match(r'\w+', u'caf\xe9!')), info(re.match(r'\w+', 'caf\xe9!')),
    info(re.match(r'\d+', u'12\u0663x', re.U)), info(re.match(r'\d+', u'12\u0663x')), info(re.match(r'\s+', u'\u3000 x', re.U)),
    info(re.match(r'\s+', u'\u3000 x')), info(re.match(u'\u00c9', u'\u00e9', re.I | re.U)), info(re.match(u'\u00c9', u'\u00e9', re.I)),
    info(re.match(u'[\u0400-\u04ff]+', u'\u0416\u0436x')), info(re.match(u'[\u0416]+', u'\u0436\u0416', re.I | re.U)),
    info(re.search(r'\bb', u'a\xe9b', re.U)), info(re.search(r'\bb', u'a\xe9b')), info(re.match(r'\W', u'\xe9', re.U)),
    info(re.match(r'(?i)ab', 'AB')), info(re.match(r'(?iu)\xe9', u'\xc9')), info(re.match(r'(?m)^b$', 'b\n')), info(re.match(r'(?x) a b # c', 'ab')),
    info(re.match(r'\w+', 'abc_1-', re.L)), info(re.match(r'[a-z]+', 'ABc', re.I | re.L)), info(re.search(r'\b\w', ' a', re.L)),
    info(re.match(r'[\w]+', u'\xe9\xe8', re.U)), info(re.match(r'[^\W\d]+', u'ab1')), info(re.match(r'[\S]+', 'ab c')), info(re.match(r'[\D]+', 'ab1')),
    info(re.search(u'[\u2603]', u'a\u2603')),
    info(re.match(r'(?i)[k]', u'\u212a', )), info(re.match(r'(?iu)[k]', u'\u212a')), re.findall(r'(?i)[a-z]', 'aBc'),
]
