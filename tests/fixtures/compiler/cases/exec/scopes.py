module_level = 1

def uses_global():
    return module_level

def uses_builtin():
    return len

def locals_call():
    a = 1
    return locals()

class ClassScope:
    attribute = module_level
    def method(self):
        return attribute

def function_with_class(x):
    class Inner:
        x = x
        y = x
    return Inner

def function_with_class_free(x):
    class Inner:
        def get(self):
            return x
    return Inner

def class_cell(x):
    class Inner:
        y = x
        def get(self):
            return y
    return Inner

def generator_free(values):
    return (value + module_level for value in values)

def import_star_free(a):
    def inner():
        return a
    return inner

def lambda_default_scope(a):
    return lambda b=a: a + b
