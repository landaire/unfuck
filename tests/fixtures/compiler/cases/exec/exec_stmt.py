code = 'x = 1'
exec code
exec code in {}
exec code in {}, {}
exec(code)
exec(code, {})

def unqualified(source):
    exec source

def qualified(source, namespace):
    exec source in namespace
    exec source in namespace, namespace

def with_closure(source):
    value = 1
    def inner():
        exec source in {}
        return value
    return inner
