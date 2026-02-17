#!/usr/bin/env python3
"""Fix Float-Float comparisons in compare.rs that got wrongly .lock().unwrap()'d."""

with open("G:/dev/unfuck/src/smallvm/compare.rs", "r") as f:
    content = f.read()

# These are all Float-Float comparisons that should be plain l op r
for op_str in ["<", "<=", "==", "!=", ">", ">="]:
    escaped = op_str
    old = f"Obj::Float(r) => stack.push((Some(Obj::Bool(*l.lock().unwrap() {escaped} *r.lock().unwrap())), left_modifying_instrs)),"
    new = f"Obj::Float(r) => stack.push((Some(Obj::Bool(l {escaped} r)), left_modifying_instrs)),"
    count = content.count(old)
    if count > 0:
        content = content.replace(old, new)
        print(f"Fixed Float-Float '{op_str}': {count} replacements")
    else:
        print(f"WARNING: Float-Float '{op_str}' pattern not found")

with open("G:/dev/unfuck/src/smallvm/compare.rs", "w") as f:
    f.write(content)

print("Done")
