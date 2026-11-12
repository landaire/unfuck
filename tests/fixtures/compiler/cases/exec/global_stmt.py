counter = 0

def increment():
    global counter
    counter += 1

def declare_many():
    global a, b
    a = b = 1

def global_in_nested():
    def inner():
        global counter
        return counter
    counter = 2
    return inner

class Holder:
    global counter
    counter = 5

def used_before_global():
    value = counter
    global counter
    return value
