def identity(f):
    return f

def factory(*args):
    return identity

@identity
def single():
    pass

@identity
@factory(1, 2)
@factory
def stacked(a):
    return a

class Holder(object):
    @staticmethod
    def static():
        pass

    @classmethod
    def klass(cls):
        return cls

    @property
    def value(self):
        return 1

@identity
class Decorated:
    pass

@factory(lambda: 0)
class DecoratedArgs(object):
    pass
