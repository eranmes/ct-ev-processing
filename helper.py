from bitstring import BitArray, Bits, BitStream

def calculate_hashes_diff(first, second):
    i = 0
    while first[i] == second[i]:
        i += 1
    assert i < 64
    return second[i:]


def calculate_diffs_array(hashes_list, hash_length):
    # Must be sorted for delta diff to make sense
    assert sorted(hashes_list)
    # Must not contain duplicates.
    assert len(hashes_list) == len(set(hashes_list))
    hash_len_bits = hash_length * 8
    ret_array = []

    prev = BitArray(bytes = hashes_list[0], length=hash_len_bits)
    for curr_hash in hashes_list[1:]:
        curr = BitArray(bytes=curr_hash, length=hash_len_bits)
        ret_array.append(calculate_hashes_diff(prev, curr))
        prev = curr
    return ret_array

