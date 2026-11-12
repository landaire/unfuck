import sys
reload(sys)
before = sys.getdefaultencoding()
sys.setdefaultencoding('utf-8')
try:
    mixed = (
        'caf\xc3\xa9' == u'caf\xe9',
        u'x' + 'caf\xc3\xa9',
        str(u'\xe9'),
        {'caf\xc3\xa9': 1}.get(u'caf\xe9'),
        '%s/%s' % ('caf\xc3\xa9', u'\u20ac'),
        sys.getdefaultencoding(),
    )
finally:
    sys.setdefaultencoding('ascii')

try:
    u'x' + '\xc3'
    failed = None
except UnicodeDecodeError as error:
    failed = (str(error), error.start, error.end, error.reason)

RESULT = (before, mixed, failed)
