#!/usr/bin/env python

from collections import namedtuple
import hashlib
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


def read_hashes(from_file, hash_length):
    with open(from_file, "rb") as f:
        raw_hashes = f.read()
        return [raw_hashes[i * hash_length:(i + 1) * hash_length]
                for i in range(len(raw_hashes) // hash_length)]


def create_delta_diff(hashes_list, hash_length):
    assert sorted(hashes_list)
    hash_len_bits = hash_length * 8
    outarray = BitArray(bytes = hashes_list[0], length=hash_len_bits)

    prev = BitArray(bytes = hashes_list[0], length=hash_len_bits)
    for curr_hash in hashes_list[1:]:
        curr = BitArray(bytes=curr_hash, length=hash_len_bits)
        i = 0
        while prev[i] == curr[i]:
            i += 1
        assert i < 64
        bits_differ = hash_len_bits - i
        outarray.append(Bits(uint=bits_differ, length=7))
        diferring_bits = curr[i:]
        #print i, bits_differ, diferring_bits.length
        assert bits_differ == diferring_bits.length
        outarray.append(diferring_bits)
        prev = curr
    return outarray.tobytes()


def uncompress_delta_diff(compressed_input, hash_length):
    ret_list = []
    instream = BitStream(bytes=compressed_input, length=len(compressed_input) * 8)
    hash_len_bits = hash_length * 8
    prev = instream.read("bits:%d" % hash_len_bits)
    ret_list.append(prev.tobytes())
    while instream.bitpos < instream.length:
        curr_diff_len = instream.read("uint:7")
        curr_diff = instream.read("bits:%d" % curr_diff_len)
        if curr_diff_len == hash_len_bits:
            curr_item = curr_diff
        else:
            curr_item = prev[:hash_len_bits - curr_diff_len] + curr_diff
            assert curr_item.length == hash_len_bits
        ret_list.append(curr_item.tobytes())
        prev = curr_item
    return ret_list



def main():
    hashes = read_hashes(FLAGS.input, FLAGS.hash_length)
    hashes.sort()
    delta_diff_bytes = create_delta_diff(hashes, FLAGS.hash_length)
    print "Delta diff size is %d, compression ratio %f" % (
            len(delta_diff_bytes), len(delta_diff_bytes) / float(len(hashes) * FLAGS.hash_length))
    with open(FLAGS.output, 'wb') as f:
        f.write(delta_diff_bytes)
    uncompressed_hashes = uncompress_delta_diff(delta_diff_bytes, FLAGS.hash_length)
    with open("/tmp/uncompressed_hashes", "wb") as f:
        for h in uncompressed_hashes:
            f.write(h.encode("hex") + "\n")
    print "Original hashes: %d  Uncompressed: %d" % (len(hashes), len(uncompressed_hashes))
    assert uncompressed_hashes == hashes

if __name__ == '__main__':
    sys.argv = FLAGS(sys.argv)
    main()
