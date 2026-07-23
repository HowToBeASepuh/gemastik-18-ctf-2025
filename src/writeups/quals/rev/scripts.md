---
layout: challenge.njk
title: Scripts
category: Rev
part: Quals
points: 100
setter: aimardcr
author: faizath
flag: "GEMASTIK18{ez_scripting_language}"
flagTeaser: "GEMASTIK18{ez_scripting...}"
description: "Scripting != Coding (or is it?). A Linux executable that <em>looks</em> like an ordinary flag checker but hides its verification logic in embedded Lua."
attachments:
  - { name: main, path: /files/quals/scripts/main, note: "the challenge ELF64 binary" }
tags: [lua, embedded, xor]
---

## Overview

We are given a Linux executable that, at first glance, looks like an ordinary flag checker —
but it actually hides its verification logic behind embedded scripting.

Initial recon: `file` reports a statically linked **ELF64**, and `strings -n 6` surfaces artifacts
like `Flag: `, `WRONG`, and several Lua-specific tokens (`_ENV`, `global`, `error string`). This
strongly suggests the binary embeds and executes a **Lua script** in memory, rather than checking
the flag directly with arithmetic in C.

## Analysis

Following the execution flow, the program first reads user input and checks its length. If it is
not exactly **33 characters**, it prints `WRONG` immediately. After the length check passes, it
extracts a blob from `.rodata`, decodes it byte-by-byte by XOR-ing with `0xA0` into a heap buffer,
and then performs a placeholder substitution: a run of 33 asterisks
(`"*********************************"`) inside the script is replaced with our input. The decoded
buffer is then parsed and run through the Lua embedding API (`luaL_loadbuffer` followed by
`lua_pcall`). In other words, the real verification lives in a Lua script into which our input is
injected at exactly the right position.

The recovered Lua checker looks like this:

```lua
ops = {"j3s5l", "j3s5l", "m9kp2", "qwx7z", ...}
k = {143, 193, 38, 93, 97, 13, ...}
pt = "*********************************"
ct = {200, 132, 39, 158, 180, 71, ...}

for i = 1, #pt do
  local op_name = ops[i]
  local key_val = k[i]
  local char_code = string.byte(pt, i)
  local result = 0

  if op_name == "qwx7z" then
    result = qwx7z(char_code, key_val)
  elseif op_name == "m9kp2" then
    result = m9kp2(char_code, key_val)
  elseif op_name == "j3s5l" then
    result = j3s5l(char_code, key_val)
  end

  if result ~= ct[i] then
    print("WRONG"); os.exit(1)
  end
end

print("CORRECT")
```

Each of the three operations `qwx7z` / `m9kp2` / `j3s5l` is one of ADD / SUB / XOR applied
position-by-position, combining our input character (`char_code`) with a per-position key
(`key_val`), and comparing against the expected ciphertext `ct[i]`.

## Solution

Because each position is independent, we can invert the check deterministically per element:

- if `ops[i]` is **ADD** → `char = ct[i] − k[i]`
- if `ops[i]` is **SUB** → `char = ct[i] + k[i]`
- if `ops[i]` is **XOR** → `char = ct[i] ^ k[i]`

Applying the inverse across all 33 positions yields the ASCII string that makes up the plaintext.
This can be done directly in a small Python script after copying the three arrays (`ops`, `k`, `ct`)
out of the decoded Lua, or even patched into a standalone solver without running the binary at all.

The result is consistent with the length check (33 characters) and verified against the program
directly: feeding the inverted string back makes it print `CORRECT`.
