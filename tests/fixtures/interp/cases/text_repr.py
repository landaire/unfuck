RESULT = (
    repr('abc'), repr("it's"), repr('say "hi"'), repr('both \' and "'), repr('\t\n\r\\\x00\x7f\x80\xff'),
    repr(u'abc'), repr(u"it's"), repr(u'both \' and "'), repr(u'\t\n\r\\\x00\x7f\x80\xff\u0100\uffff'),
    repr(u'\ud800'), repr(u'\udc00x'), repr(''), repr(u''), repr(('a', u'b')),
    'a\x00b', u'\x1f\x7e',
)
