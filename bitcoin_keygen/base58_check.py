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
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""Base58Check Functions"""

import binascii
import hashlib

__all__ = ["encode", "decode", "checksum_check"]

CODE_STR = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
INV_CODE_STR = dict(zip(CODE_STR, range(58)))


def encode(version, payload):
    """creates a Base58Check string from a version byte and payload"""
    # concatenate the version and payload
    ext_key = version + payload

    # take the checksum of the extended key
    checksum = hashlib.sha256(
        hashlib.sha256(binascii.unhexlify(ext_key)).digest()
    ).hexdigest()[:8]

    # concatenate the external key and checksum
    ext_key += checksum

    # convert the external key to base-58
    x = int(ext_key, 16)
    out_str = []
    while x > 0:
        x, rem = divmod(x, 58)
        out_str.append(CODE_STR[rem])

    # represent leading zero bytes by '1'
    leading_ones = "1" * ((len(ext_key) - len(ext_key.lstrip("0"))) // 2)

    # concatenate the 1's with the external key in base-58
    return leading_ones + "".join(reversed(out_str))


def decode(base58_str):
    """decodes a Base58Check string to a version byte and payload"""
    # strip leading 1's
    out_str = base58_str.lstrip("1")[::-1]

    # construct byte string
    x = sum(INV_CODE_STR[char] * pow(58, i) for i, char in enumerate(out_str))
    byte_str = hex(x)[2:]
    leading_zeroes = "00" * (len(base58_str) - len(out_str)) + "0" * (len(byte_str) & 1)
    byte_str = leading_zeroes + byte_str

    # drop checksum
    return byte_str[:2], byte_str[2:-8]


def checksum_check(base58_str):
    """check if a Base58Check string is valid"""
    return encode(*decode(base58_str)) == base58_str
