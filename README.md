# unfuck

Have fucked Python 2.7 bytecode? Let's `unfuck` it.

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

## Overview

`unfuck` is a utility and library for `unfuck`ing obfuscated Python 2.7 bytecode. It is essentially a reimplementation of the Python VM with taint tracking. Some of the things `unfuck` can do:

1. Remove opaque predicates
2. Dead code elimination
3. Restore some lost function names
4. Cleanup obfuscated variable names

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
4. Variable/function names may become obfuscated into non-valid Python identifiers. e.g. `cache` may become something like `for u global set :`.

### Deobfusation Passes

At a high-level, `unfuck` operates as follows:

1. The bytecode is walked and disassembled from the very first instruction.
2. When a jump is encountered, both branches are queued for parsing *unless* the jump is to an invalid target.
3. When a "terminating" instruction (such as a `RETURN_VALUE`) is encountered no more parsing happens down that execution path.
4. When all instructions are parsed, a graph structure is built to construct all basic blocks (BBs).

Once the graph is constructed:

1. BBs with bad/invalid instructions are replaced with a `POP_TOP`. This *sometimes* helps with decompilation by balancing the stack if constant propagation fails later on and a code path cannot be eliminated.
2. Unnecesary `JUMP_FORWARD` instructions are eliminated and BBs that can be joined into one are joined.
3. Const conditions/opaque predicates are removed. This is where VM execution occurs and taint tracking happens. The process of taint tracking is fairly simple: if a value is constant or *derived* from constants, its value is pushed to the VM stack as `(Some(Value), Vec<InstructionIndex>)` where the vector contains every instruction which helped construct the `Some(Value)`. If the value *cannot* be determined, its value is simply `(None, vec![])`. When a conditional jump is encountered, we look at the top-of-stack (TOS) value and if it is `Some(...)`, we can evaluate which branch would be taken and remove the other code path (taking into consideration paths that are provably always executed and paths that we cannot prove will not be executed).
-- An example of something we can figure out is `if {1, 2, 3} & {2}: ...`. The two sets are loaded as consts and an intersecting set is created via the `&` operator. The result is a set containing `{2}`, which as a truthy value, evaluates to `True`.
-- An example of something we cannot figure out is:  

```python
def some_custom_function():
    True
if some_custom_function():
    ...
```

In theory this would not be too difficult to evaluate, but is not simple to architect in a clean way.

4. After opaque predicates are removed, we simplify the BBs again.
5. We update the BB offsets to be "normal". We just removed a bunch of code, so we need any relative/absolute offsets referenced in the instructions to match what they would be in a file.
6. `RETURN_VALUE` calls are "massaged" so that a decompiler can make better sense of it. e.g. if a value is returned in a for loop *and* outside of the for loop, sometimes the decompiler will have a difficult time representing this cleanly. This will duplicate the `RETURN_VALUE` into its own basic block.
7. BB offsets are updated
8. `JUMP_FORWARD 0` instructions are inserted in certain locations to help match "interesting" bytecode generated by the compiler. This `JUMP_FORWARD` may have been lost when we joined basic blocks, or perhaps it was never picked up because it came after a terminating instruction... but the decompiler may depend on this in order to figure out if something is an `if/else`.
9. BB offsets are updated.
10. New bytecode is serialized.

This process means that if an instruction cannot be naturally exercised through the VM, it will not be parsed. For example:

```
JUMP_FORWARD 3
POP_TOP
POP_TOP
POP_TOP
LOAD_CONST 0
RETURN_VALUE
```

The 3 `POP_TOP` instructions will never be queued for disassembly since there is no way for a real VM to ever exercise this code path. It also means that there may be some cases where dead code cannot safely be eliminated.

### Limitations

`unfuck` currently does not handle the following scenarios:

- Some set operations.
- Some dict operations.
- Constant propagation across code objects.
- No out-of-box support for remapped opcodes, although this could be done trivially.

## Debugging

### Graphs

It may be useful to try figuring out why decompiling some deobfuscated code did not work. One of the most helpful debugging tools is viewing the Graphviz graphs betweeen passes in the deobfuscator and diffing changes. When using `unfuck` you can pass the `-g` flag which will create `.dot` files in your current directory. The names of these files are formatted as follows:

```rust
        let filename = format!(
            "{}_phase{}_{}_{}_{}.dot",
            self.file_identifier, // unique file index
            self.phase, // phase number that can be used to find the first/last deobfuscation stage
            stage, // the last "major" operation that occurred
            self.code.filename.to_string().replace("/", ""), // the python code object's filename
            self.code.name.to_string().replace("/", ""), // the python code object's name
        );
```

You can paste paste the contents of these files on [https://dreampuf.github.io/GraphvizOnline] to generate an SVG of the bytecode's call graph.

### Hand-Crafted, Artisan PYC Files

@gabe_k developed a tool called `pyasm` which can disassemble `.pyc` files into a custom format called a `.pyasm` file. You can modify the contents of the `.pyasm` file to remove unwanted unwanted instructions, recompile-it with the `makepy` command, and attempt decompilation again. This may help understand what patterns are tripping up the decompiler.

pyasm can be found here: https://github.com/gabe-k/pyasm

There are a couple of quality-of-life features on my own branch that are useful for rapid testing: https://github.com/landaire/pyasm


## greetz

gabe_k, _yrp