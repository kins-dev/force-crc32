#!/usr/bin/env python3
# 
# CRC-32 forcer (Python)
# 
# Copyright (c) 2020 Project Nayuki
# https://www.nayuki.io/page/forcing-a-files-crc-to-any-value
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
# along with this program (see COPYING.txt).
# If not, see <http://www.gnu.org/licenses/>.
# 

import os, sys, zlib, argparse, re, pprint
from sys import version
from typing import BinaryIO, List, Optional, Tuple

__version__ = "1.00.0"

# ---- Constants ----
def constant(f):
	def f_set(self, value):
		raise TypeError
	def f_get(self):
		return f()
	return property(f_get, f_set)

class _Const(object):
	@constant
	def POLYNOMIAL() -> int:
		# Generator polynomial. Do not modify, because there are many dependencies
		return 0x104C11DB7

	@constant
	def MAX_VALUE() -> int:
		return (1 << 32) - 1
	
	@constant
	def MIN_VALUE() -> int:
		return -1 * (1 << 31)
	
	@constant
	def VERSION() -> str:
		return "1.0"

CONST = _Const()

# ---- ArgParse Functions ----
class SmartFormatter(argparse.ArgumentDefaultsHelpFormatter): 
	def add_text(self, text):
		try:
			for line in text.split("\0"):
				super().add_text(line)
		except:
			pass

def crc_value(value: str) -> int:
	result:int = int(value, 0)
	if CONST.MIN_VALUE <= result and CONST.MAX_VALUE >= result:
		raise argparse.ArgumentTypeError("CRC must be a 32-bit value")
	if 0 > result:
		return result & CONST.MASK
	return result

# ---- Main application ----

def main() -> Optional[str]:
	try:
		parser = argparse.ArgumentParser(
			prog="forcecrc32",
			description="""Forces a file to have a particular CRC32 value""",
			epilog="""If the file does not exist and the offset is 0 or not set, a new 
					4 byte file will be created.\0\0CRC-32 must be between {min_value} 
					and {max_value} or {min_value_hex} and {max_value_hex}. Negative
					numbers will have the standard 2's compliment applied to get the CRC
					hex value.""".format(min_value=CONST.MIN_VALUE,
										max_value=CONST.MAX_VALUE,
										min_value_hex="0x{v:08X}".format(v=0),
										max_value_hex="0x{v:08X}".format(v=CONST.MAX_VALUE)),
			formatter_class=SmartFormatter)
		parser.add_argument('-v', '--version', action='version',
				version='%(prog)s {version} Copyright (c) 2020 scott@kins.dev'.format(version=__version__))
		parser.add_argument("file", type=str, help="File to open")
		parser.add_argument("crc", type=crc_value, help="Target crc. Use 0x to prefix a hex value")
		parser.add_argument("offset", type=int, nargs='?',default=0, help="Where to write the new data (default 0)")
		parser.add_argument("-q", "--quiet", action="store_true", help="Show only errors")
		args = parser.parse_args()
		if args.offset < 0:
			return "Error: Negative byte offset"
	
	# Process the file
		modify_file_crc32(args.file, args.offset, args.crc, not args.quiet)
	except IOError as e:
		return "I/O error: " + str(e)
	except ValueError as e:
		return "Error: " + str(e)
	except AssertionError as e:
		return "Assertion error: " + str(e)
	return None


# ---- Main function ----

# Public library function. offset is uint, and newcrc is uint32.
# May raise IOError, ValueError, AssertionError.
def modify_file_crc32(path: str, offset: int, target_crc: int, printstatus: bool = False) -> None:
	if not os.path.exists(path) and 0 == offset:
		if printstatus:
			print("File does not exist, creating 4 byte file")
		with open(path, "wb") as file_stream:
			file_stream.write(bytearray([0,0,0,0]))

	with open(path, "r+b") as file_stream:
		file_stream.seek(0, os.SEEK_END)
		length: int = file_stream.tell()
		if offset + 4 > length:
			raise ValueError("Error: The offset must be at least 4 bytes before the end of the file")
		
		# Read entire file and calculate original CRC-32 value
		file_crc: int = get_crc32(file_stream)
		if printstatus:
			print(f"Current CRC-32: 0x{reverse32(file_crc):08X}")
			print(f"Target CRC-32:  0x{target_crc:08X}")
		
		# Compute the change to make
		delta: int = file_crc ^ reverse32(target_crc)
		delta = multiply_mod(reciprocal_mod(pow_mod(2, (length - offset) * 8)), delta)
		
		# Patch 4 bytes in the file
		file_stream.seek(offset)
		bytes4: bytearray = bytearray(file_stream.read(4))
		if len(bytes4) != 4:
			raise IOError("Cannot read 4 bytes at offset")
		for i in range(4):
			bytes4[i] ^= (reverse32(delta) >> (i * 8)) & 0xFF
		file_stream.seek(offset)
		file_stream.write(bytes4)
		if printstatus:
			print("Computed and updated file")
		
		# Recheck entire file
		output_crc: int = reverse32(get_crc32(file_stream))
		if output_crc != target_crc:
			raise AssertionError("Failed to update CRC-32 to desired value")
		if printstatus:
			print(f"Current CRC-32: 0x{output_crc:08X}")


# ---- Utilities ----

def get_crc32(file_stream: BinaryIO) -> int:
	file_stream.seek(0)
	crc: int = 0
	while True:
		buffer: bytes = file_stream.read(128 * 1024)
		if len(buffer) == 0:
			return reverse32(crc)
		crc = zlib.crc32(buffer, crc)


def reverse32(x: int) -> int:
	y: int = 0
	for _ in range(32):
		y = (y << 1) | (x & 1)
		x >>= 1
	return y


# ---- Polynomial arithmetic ----

# Returns polynomial x multiplied by polynomial y modulo the generator polynomial.
def multiply_mod(x: int, y: int) -> int:
	# Russian peasant multiplication algorithm
	z: int = 0
	while y != 0:
		z ^= x * (y & 1)
		y >>= 1
		x <<= 1
		if (x >> 32) & 1 != 0:
			x ^= CONST.POLYNOMIAL
	return z


# Returns polynomial x to the power of natural number y modulo the generator polynomial.
def pow_mod(x: int, y: int) -> int:
	# Exponentiation by squaring
	z: int = 1
	while y != 0:
		if y & 1 != 0:
			z = multiply_mod(z, x)
		x = multiply_mod(x, x)
		y >>= 1
	return z


# Computes polynomial x divided by polynomial y, returning the quotient and remainder.
def divide_and_remainder(x: int, y: int) -> Tuple[int,int]:
	if y == 0:
		raise ValueError("Division by zero")
	if x == 0:
		return (0, 0)
	
	y_deg: int = get_degree(y)
	z: int = 0
	for i in range(get_degree(x) - y_deg, -1, -1):
		if (x >> (i + y_deg)) & 1 != 0:
			x ^= y << i
			z |= 1 << i
	return (z, x)


# Returns the reciprocal of polynomial x with respect to the modulus polynomial m.
def reciprocal_mod(x: int) -> int:
	# Based on a simplification of the extended Euclidean algorithm
	y: int = x
	x = CONST.POLYNOMIAL
	a: int = 0
	b: int = 1
	while y != 0:
		q, r = divide_and_remainder(x, y)
		c = a ^ multiply_mod(q, b)
		x = y
		y = r
		a = b
		b = c
	if x == 1:
		return a
	else:
		raise ValueError("Reciprocal does not exist")


def get_degree(x: int) -> int:
	return x.bit_length() - 1


# ---- Miscellaneous ----

if __name__ == "__main__":
	errmsg = main()
	if errmsg is not None:
		sys.exit(errmsg)
