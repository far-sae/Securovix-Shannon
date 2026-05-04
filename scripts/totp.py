#!/usr/bin/env python3
"""TOTP code generator for Shannon authentication flows."""

import sys
import hmac
import hashlib
import struct
import time
import base64


def generate_totp(secret: str, interval: int = 30, digits: int = 6) -> str:
    """Generate a TOTP code from a base32-encoded secret."""
    # Decode the base32 secret
    key = base64.b32decode(secret.upper().replace(' ', ''), casefold=True)

    # Get current time step
    time_step = int(time.time()) // interval

    # Pack time step as big-endian 8-byte integer
    time_bytes = struct.pack('>Q', time_step)

    # Compute HMAC-SHA1
    hmac_hash = hmac.new(key, time_bytes, hashlib.sha1).digest()

    # Dynamic truncation
    offset = hmac_hash[-1] & 0x0F
    truncated = struct.unpack('>I', hmac_hash[offset:offset + 4])[0]
    truncated &= 0x7FFFFFFF

    # Generate code with specified digits
    code = truncated % (10 ** digits)
    return str(code).zfill(digits)


def main() -> None:
    if len(sys.argv) < 2:
        print('Usage: totp-generator <base32-secret> [interval] [digits]', file=sys.stderr)
        sys.exit(1)

    secret = sys.argv[1]
    interval = int(sys.argv[2]) if len(sys.argv) > 2 else 30
    digits = int(sys.argv[3]) if len(sys.argv) > 3 else 6

    code = generate_totp(secret, interval, digits)
    print(code)


if __name__ == '__main__':
    main()
