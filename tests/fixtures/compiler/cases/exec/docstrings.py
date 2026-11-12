"""Module docstring
spanning lines."""

def documented():
    "Function docstring."
    return 1

def not_first():
    x = 1
    "not a docstring"
    return x

def unicode_doc():
    u"Unicode docstring \xe9."

def only_doc():
    """Only a docstring."""

def concatenated():
    "first " 'second'

def number_first():
    1
    "not a docstring either"

class Documented:
    """Class docstring."""
    def method(self):
        """Method docstring."""

class Undocumented:
    x = "not a docstring"

lambda_doc = lambda: "lambda docstring"
