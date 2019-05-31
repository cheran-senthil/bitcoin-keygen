#!/usr/bin/env python
"""Bitcoin Keygen"""
# Copyright (C) 2019 Cheran Senthilkumar
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import binascii
import hashlib


def is_private_valid(private_key):
    """check if a given private key is valid"""
    N = (1 << 256) - 0x14551231950B75FC4402DA1732FC9BEBF  # order
    return 0 < int(private_key, 16) < N


def Base58Check_encoding(version, payload):
    """creates a Base58Check string from a version byte and payload"""
    code_str = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

    # concatenate the version and payload
    ext_key = version + payload

    # take the checksum of the extended key
    checksum = hashlib.sha256(hashlib.sha256(binascii.unhexlify(ext_key)).digest()).hexdigest()[:8]

    # concatenate the external key and checksum
    ext_key += checksum

    # convert the external key to base-58
    x = int(ext_key, 16)
    out_str = []
    while x > 0:
        x, rem = divmod(x, 58)
        out_str.append(code_str[rem])

    # represent leading zero bytes by '1'
    leading_ones = '1' * ((len(ext_key) - len(ext_key.lstrip('0'))) // 2)

    # concatenate the 1's with the external key in base-58
    return leading_ones + ''.join(reversed(out_str))


def private2WIF(private_key, compressed=False, mainnet=True):
    """returns the Wallet Import Format (WIF) associated with a private key (hex string)"""
    if not is_private_valid(private_key):
        raise ValueError("{} is not a valid key".format(private_key))
    return Base58Check_encoding('80' if mainnet else 'ef', private_key + ('01' if compressed else ''))


def private2public(private_key, compressed=False):
    """returns the public key associated with a private key (hex string)"""
    if not is_private_valid(private_key):
        raise ValueError("{} is not a valid key".format(private_key))

    # base point (generator)
    G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
         0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

    # field prime
    P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

    def elliptic_add(p, q):
        """addition operation on the elliptic curve"""
        px, py = p
        qx, qy = q

        if p == q:
            lam = (3 * px * px) * pow(2 * py, P - 2, P)
        else:
            lam = (qy - py) * pow(qx - px, P - 2, P)

        rx = lam * lam - px - qx
        ry = lam * (px - rx) - py
        return (rx % P, ry % P)

    # compute G * private_key with repeated addition
    x = int(private_key, 16)
    p = None
    for i in range(256):
        if x & (1 << i):
            p = G if p is None else elliptic_add(p, G)
        G = elliptic_add(G, G)

    px, py = p
    if compressed:
        return ('03' if py & 1 else '02') + hex(px)[2:]
    return '04' + hex(px)[2:] + hex(py)[2:]


def public2address(public_key, mainnet=True):
    """returns the address associated with a public key"""
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(hashlib.sha256(binascii.unhexlify(public_key)).digest())
    return Base58Check_encoding('00' if mainnet else '6f', ripemd160.hexdigest())


def private2address(private_key, compressed=False, mainnet=True):
    """returns the address associated with a private key"""
    if not is_private_valid(private_key):
        raise ValueError("{} is not a valid key".format(private_key))
    public2address(private2public(private_key, compressed), mainnet)
