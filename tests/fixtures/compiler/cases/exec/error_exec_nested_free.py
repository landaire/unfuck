def outer(a, code):
    exec code
    def inner():
        return a
    return inner
