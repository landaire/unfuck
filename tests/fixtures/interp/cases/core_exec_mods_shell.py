REGISTERED = []


def register(name):
    def decorate(function):
        REGISTERED.append((name, function.__name__, function.__module__))
        return function

    return decorate


SOURCE = '''
@register('greeting')
def greet(who):
    return 'hello ' + who

answer = greet('mods')
'''

exec SOURCE in globals()

RESULT = (REGISTERED, answer, greet('again'), greet.func_code.co_filename, greet.func_globals is globals())
