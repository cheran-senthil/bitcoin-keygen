#!/usr/bin/env python

import binascii
import hashlib


def Base58Check_encoding(version, payload):
    """creates a Base58Check string from a version byte and payload"""
    code_str = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

    ext_key = version + payload
    checksum = hashlib.sha256(hashlib.sha256(binascii.unhexlify(ext_key)).digest()).hexdigest()[:8]
    ext_key += checksum
    leading_ones = '1' * ((len(ext_key) - len(ext_key.lstrip('0'))) // 2)

    x = int(ext_key, 16)
    out_str = []
    while x > 0:
        x, rem = divmod(x, 58)
        out_str.append(code_str[rem])

    return leading_ones + ''.join(reversed(out_str))


def private2WIF(private_key, compressed=False, mainnet=True):
    """returns the Wallet Import Format (WIF) of a given private key (hex string)"""
    return Base58Check_encoding('80' if mainnet else 'ef', private_key + ('01' if compressed else ''))


def private2public(private_key, compressed=False):
    """returns the public key associated with a private key"""
    private_key = int(private_key, 16)

    P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    N = (1 << 256) - 0x14551231950B75FC4402DA1732FC9BEBF
    G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
         0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

    if not (0 < private_key < N):
        raise ValueError("{} is not a valid key (not in range [1, {}])".format(hex(private_key), hex(N - 1)))

    def add_elliptic(p, q):
        """returns the point addition of p and q"""
        px, py = p
        qx, qy = q

        if p == q:
            lam = (3 * px * px) * pow(2 * py, P - 2, P)
        else:
            lam = (qy - py) * pow(qx - px, P - 2, P)

        rx = lam * lam - px - qx
        ry = lam * (px - rx) - py
        return (rx % P, ry % P)

    p = None
    for i in range(256):
        if private_key & (1 << i):
            p = G if p is None else add_elliptic(p, G)
        G = add_elliptic(G, G)

    x, y = p
    if compressed:
        return ('03' if y & 1 else '02') + hex(x)[2:]
    return '04' + hex(x)[2:] + hex(y)[2:]


def public2address(public_key, mainnet=True):
    """returns the address associated with a public key"""
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(hashlib.sha256(binascii.unhexlify(public_key)).digest())
    return Base58Check_encoding('00' if mainnet else '6f', ripemd160.hexdigest())


def private2address(private_key, compressed=False, mainnet=True):
    """returns the address associated with a private key"""
    public2address(private2public(private_key, compressed), mainnet)
