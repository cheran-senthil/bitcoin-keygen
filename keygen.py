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


class Base58Check:
    code_str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    inv_code_str = dict(zip(code_str, range(58)))

    @classmethod
    def encode(cls, version, payload):
        """creates a Base58Check string from a version byte and payload"""
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
            out_str.append(cls.code_str[rem])

        # represent leading zero bytes by '1'
        leading_ones = "1" * ((len(ext_key) - len(ext_key.lstrip("0"))) // 2)

        # concatenate the 1's with the external key in base-58
        return leading_ones + "".join(reversed(out_str))

    @classmethod
    def decode(cls, base58_str):
        """decodes a Base58Check string to a version byte and payload"""
        # strip leading 1's
        out_str = base58_str.lstrip("1")[::-1]

        # construct byte string
        x = sum(cls.inv_code_str[char] * pow(58, i) for i, char in enumerate(out_str))
        byte_str = hex(x)[2:]
        leading_zeroes = "00" * (len(base58_str) - len(out_str)) + "0" * (len(byte_str) & 1)
        byte_str = leading_zeroes + byte_str

        # drop checksum
        return byte_str[:2], byte_str[2:-8]


def is_private_valid(private_key):
    """check if a given private key is valid"""
    N = (1 << 256) - 0x14551231950B75FC4402DA1732FC9BEBF  # order
    return 0 < int(private_key, 16) < N


def private2public(private_key, compressed=False):
    """returns the public key associated with a private key (hex string)"""
    if not is_private_valid(private_key):
        raise ValueError("{} is not a valid key".format(private_key))

    # base point (generator)
    G = (
        0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
    )

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
        return ("03" if py & 1 else "02") + hex(px)[2:]
    return "04" + hex(px)[2:] + hex(py)[2:]


def public2address(public_key, mainnet=True):
    """returns the address associated with a public key"""
    ripemd160 = hashlib.new("ripemd160")
    ripemd160.update(hashlib.sha256(binascii.unhexlify(public_key)).digest())
    return Base58Check.encode("00" if mainnet else "6f", ripemd160.hexdigest())


def private2address(private_key, compressed=False, mainnet=True):
    """returns the address associated with a private key"""
    if not is_private_valid(private_key):
        raise ValueError("{} is not a valid key".format(private_key))
    return public2address(private2public(private_key, compressed), mainnet)


def private2WIF(private_key, compressed=False, mainnet=True):
    """returns the Wallet Import Format (WIF) associated with a private key (hex string)"""
    if not is_private_valid(private_key):
        raise ValueError("{} is not a valid key".format(private_key))
    return Base58Check.encode("80" if mainnet else "ef", private_key + ("01" * compressed))


def WIF2private(wif, compressed=False):
    """returns the private key associated with a Wallet Import Format (WIF)"""
    _, private_key = Base58Check.decode(wif)
    return private_key[:-2] if compressed else private_key
