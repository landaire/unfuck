# unfuck

Have fucked Python 2.7 bytecode? Let's `unfuck` it.

## Overview

`unfuck` is a utility and library for `unfuck`ing obfuscated Python 2.7 bytecode. It is essentially a reimplementation of the Python VM with taint tracking. Some of the things `unfuck` can do:

1. Remove opaque predicates
2. Dead code elimination
3. Restore some lost function names
4. Cleanup obfuscated variable names

#1 and #2 are the two biggest items that Python decompilers trip over when attempting to reconstruct original Python source code.


## Usage

`unfuck` can either be used as a library or a command-line utility.

```
unfuck 0.2.0

USAGE:
    unfuck [FLAGS] [OPTIONS] <input-obfuscated-file> <output-path> [graphs-dir] [SUBCOMMAND]

FLAGS:
        --dry        Dry run only -- do not write any files
    -g               Enable outputting code graphs to dot format
    -h, --help       Prints help information
    -q               Disable all logging
    -V, --version    Prints version information
    -v               Enable verbose logging

OPTIONS:
        --decompiler <decompiler>    Only dump strings frmo the stage4 code. Do not do any further processing [env:
                                     UNFUCK_DECOMPILER=]  [default: uncompyle6]

ARGS:
    <input-obfuscated-file>    Input obfuscated file
    <output-path>              Output file name or directory name. If this path is a directory, a file will be
                               created with the same name as the input. When the `strings-only` subcommand is
                               applied, this will be where the output strings file is placed
    <graphs-dir>               An optional directory for graphs to be written to [default: .]

SUBCOMMANDS:
    help            Prints this message or the help of the given subcommand(s)
    strings-only
```

To `unfuck` a single file:

```
# deobfuscated.pyc can also be a directory
unfuck obfuscated.pyc deobfuscated.pyc
```

You can also provide additional flags to dump strings to a file, or dump `dot` graphs that can be viewed in graphviz:

```
# -g is for printing graphs
unfuck -g obfuscated.pyc deobfuscated.pyc
# use the strings-only subcommand for dumping just dumping strings -- no deobfuscation is performed
unfuck deobufscated.pyc ./strings.csv strings-only
```

### Useful Wiki Resources

- [Obfuscation Tricks](https://github.com/landaire/unfuck/wiki/Obfuscation-Tricks)
- [Deobfuscation Passes](https://github.com/landaire/unfuck/wiki/Deobfuscation-Passes)
- [Debugging Failed Decompilation](https://github.com/landaire/unfuck/wiki/Debugging-Failed-Decompilation)

## greetz

gabe_k, yrp