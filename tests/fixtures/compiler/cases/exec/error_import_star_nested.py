def outer(a):
    from os import *
    def inner():
        return a
    return inner
