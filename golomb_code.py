#!/usr/bin/env python

from collections import namedtuple
import hashlib
import math
import os
import re
import sys

from bitstring import BitArray, Bits, BitStream
from ct.crypto import cert
from ct.crypto import pem

import gflags

FLAGS = gflags.FLAGS

gflags.DEFINE_string("input", "all_hashes.bin", "Input hashes file")
gflags.DEFINE_string("output", "all_hashes.ddiff", "Output, compressed file.")
gflags.DEFINE_integer("hash_length", 8, "Length of each hash in bytes.")
gflags.DEFINE_integer("two_power", 50, "Power of 2 for M (M=2**two_power).")

def read_hashes(from_file, hash_length):
    with open(from_file, "rb") as f:
        raw_hashes = f.read()
        return [raw_hashes[i * hash_length:(i + 1) * hash_length]
                for i in range(len(raw_hashes) // hash_length)]


def golomb_encode(hashes_list, hash_length, M):
    hash_len_bits = hash_length * 8
    # Must be sorted for delta diff to make sense
    assert sorted(hashes_list)
    # Must not contain duplicates.
    assert len(hashes_list) == len(set(hashes_list))
    m_bits = int(math.log(M, 2))
    assert abs(math.log(M, 2) - float(m_bits)) < 0.00001
    outarray = BitArray(bytes = hashes_list[0], length=hash_len_bits)

    min_is_zero = False
    prev = BitArray(bytes = hashes_list[0], length=hash_len_bits)
    for curr_hash in hashes_list[1:]:
        curr = BitArray(bytes=curr_hash, length=hash_len_bits)
        N = curr.uint - prev.uint
        q = int(math.floor(N / M))
        r = N % M
        if q == 0:
            outarray.append(Bits(bin='0b0'))
            min_is_zero = True
        else:
            outarray.append(Bits(bin=bin(2**q - 1) + '0'))

        outarray.append(Bits(uint=r, length=m_bits))
        prev = curr

    if not min_is_zero:
        print "Inefficient encoding: Minimum is not zero."
    return outarray.tobytes()


def uncompress_golomb_coding(coded_bytes, hash_length, M):
    ret_list = []
    instream = BitStream(
            bytes=coded_bytes, length=len(coded_bytes) * hash_length)
    hash_len_bits = hash_length * 8
    m_bits = int(math.log(M, 2))
    prev = instream.read("bits:%d" % hash_len_bits)
    ret_list.append(prev.tobytes())
    while instream.bitpos < instream.length:
        read_prefix=0
        curr_bit = instream.read("uint:1")
        while curr_bit == 1:
            read_prefix += 1
            curr_bit = instream.read("uint:1")
        assert curr_bit == 0
        r = instream.read("uint:%d" % m_bits)
        curr_diff = read_prefix * M + r
        curr_value_int = prev.uint + curr_diff
        curr_value = Bits(uint=curr_value_int, length=hash_len_bits)
        ret_list.append(curr_value.tobytes())
        prev = curr_value

    return ret_list


def main():
    hashes = read_hashes(FLAGS.input, FLAGS.hash_length)
    hashes.sort()

    golomb_coded_bytes = golomb_encode(
        hashes, FLAGS.hash_length, 2**FLAGS.two_power)

    print "With M=2**%d, Golomb-coded data size is %d, compression ratio %f" % (
            FLAGS.two_power,
            len(golomb_coded_bytes),
            len(golomb_coded_bytes) / float(len(hashes) * FLAGS.hash_length))

    with open(FLAGS.output, 'wb') as f:
        f.write(golomb_coded_bytes)

    uncompressed_hashes = uncompress_golomb_coding(
        golomb_coded_bytes, FLAGS.hash_length, 2**FLAGS.two_power)

    with open("/tmp/uncompressed_hashes", "wb") as f:
        for h in uncompressed_hashes:
            f.write(h.encode("hex") + "\n")
    print "Original hashes: %d  Uncompressed: %d" % (
        len(hashes), len(uncompressed_hashes))
    assert uncompressed_hashes == hashes

if __name__ == '__main__':
    sys.argv = FLAGS(sys.argv)
    main()
