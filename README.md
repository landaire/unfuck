# unfuck

Have fucked Python 2.7 bytecode? Let's `unfuck` it.

## Overview

`unfuck` is a utility and library for `unfuck`ing obfuscated Python 2.7 bytecode. It is essentially a reimplementation of the Python VM with taint tracking. Some of the things `unfuck` can do:

1. Remove opaque predicates
2. Dead code elimination
3. Restore some lost function names

#1 and #2 are the two biggest items that Python decompilers trip over when attempting to reconstruct original Python source code. There's a few reasons for this:

1. Some decompilers such as `uncompyle` rely on lifting the bytecode to its assembly/IL. `uncompyle` in particular uses AST matching to reconstruct the pattern that *could* have been responsible for generating that code. For example, the following pattern is used to construct an `import` statement:

```
# Load the name of the module we're about to import
IMPORT_NAME 3
# Import the module
IMPORT_FROM
# Store the module in one of our slots
STORE_NAME 3
```

An obfuscator may insert additional code inbetween any of these instructions that alters the stack state in a way that is a no-op, but throws off the pattern matching of the decompiler.

2. The obfuscators may do complex arithmetic that is split in an abnormal way. See the above point for more info, but this will also throw off reconstructing of expressions.
3. Building off of point #2, complex arithmetic may be a constant expression that always evaluates to true/false, but determining this constant value requires evaluating all dependencies of the boolean (what we call an opaque predicate). The obfuscators can use this to inject false code paths that will never actually be executed, but either jumps to a completely garbage jump target (i.e. the offset does not exist, or is at a weird location) or jumps to invalid/garbage bytecode.

## Usage

`unfuck` can either be used as a library or a command-line utility. To `unfuck` a single file:

```
unfuck obfuscated.pyc deobfuscated.pyc
```

You can also provide additional flags to dump strings to a file, or dump `dot` graphs that can be viewed in graphviz:

```
# -g is for printing graphs
unfuck -g obfuscated.pyc deobfuscated.pyc
# -s is for dumping just strings
unfuck -s strings.csv deobufscated.pyc
```

## greetz

gabe_k, _yrp