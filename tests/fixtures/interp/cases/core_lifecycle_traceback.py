import sys

log = []


class Tracked(object):
    def __init__(self, name):
        self.name = name

    def __del__(self):
        log.append('del ' + self.name)


def raiser():
    inner = Tracked('raiser local')
    raise KeyError('k')


def handler():
    try:
        raiser()
    except KeyError:
        log.append('caught')
    log.append('after handler')


handler()
log.append('after return')


def keep():
    try:
        raiser()
    except KeyError:
        return sys.exc_info()[2]


saved = keep()
log.append('saved')
del saved
log.append('released')

try:
    raiser()
except KeyError:
    log.append('module caught')
sys.exc_clear()
log.append('cleared')
RESULT = log
