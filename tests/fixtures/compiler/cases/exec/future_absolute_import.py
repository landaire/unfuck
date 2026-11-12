from __future__ import absolute_import, nested_scopes, generators
import os
from os import path
from . import sibling

def inner():
    import sys
    from .. import parent
    return sys, parent
