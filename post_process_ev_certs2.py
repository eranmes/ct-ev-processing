#!/usr/bin/env python

from collections import namedtuple
import hashlib
import multiprocessing
import os
import pickle
import re
import sys

import ev
from ct.crypto import cert
from ct.crypto import pem

import gflags

FLAGS = gflags.FLAGS

gflags.DEFINE_string("certs_dir", "individual_ev_certs", "Base directory containing all EV certs")

gflags.DEFINE_string("output_dir", "non_matching_certs", "Base directory containing all EV certs")

gflags.DEFINE_integer("multi", 1, "Number of cert parsing processes to use in "
                      "addition to the main process and the network process.")

gflags.DEFINE_integer("hash_trim", 8, "Number of bytes of the SHA-256 digest "
                      "to use in the whitelist.")

gflags.DEFINE_string("output", "ev_cert_hashes.bin", "Output filename")


def sha1(data):
  s = hashlib.sha1()
  s.update(data)
  return s.digest()


def get_certificates_list(base_dir):
    file_matcher = re.compile("cert_([0-9]+)\.der")
    return [f for f in os.listdir(base_dir) if file_matcher.match(f)]


def load_chain_for_cert_file(cert_filename):
    chain_file = cert_filename.replace(".der", "_extra_data.pickle")
    return pickle.load(
            open(os.path.join(FLAGS.certs_dir, chain_file), "rb"))


def find_matching_policy(c):
    for policy in c.policies():
        if policy['policyIdentifier'] in ev.EV_POLICIES:
            return policy['policyIdentifier']
    return None


ChainAnalysisResult = namedtuple("ChainAnalysisResult", [
  "fingerprint_matched", "fingerprint_matches_other_root"])


def analyze_cert(c, cert_filename):
  cert_chain_der = load_chain_for_cert_file(cert_filename)
  matching_policy = find_matching_policy(c)
  #assert matching_policy
  if not matching_policy:
      print 'ODD! No matching policy for ',cert_filename
  chain_fingerprints = [sha1(c.to_der())]
  for chained_cert_der in cert_chain_der:
    chain_fingerprints.append(sha1(chained_cert_der))
  fingerprint_matched = any([fp in ev.EV_POLICIES[matching_policy]
                             for fp in chain_fingerprints])
  root_may_be_cross_signed = any(
      [fp in ev.EV_ROOTS.keys() for fp in chain_fingerprints])

  return ChainAnalysisResult(
      fingerprint_matched,
      root_may_be_cross_signed)


def pem_cert_chain_for_cert(c, cert_chain_der):
    output_pem = c.to_pem() + '\n'
    for chained_cert_der in cert_chain_der:
        output_pem += pem.to_pem(chained_cert_der, "CERTIFICATE") + '\n'
    return output_pem

def write_interesting_chain(cert_filename, c, unknown_root = False):
    chain = load_chain_for_cert_file(cert_filename)
    root_cert_der = chain[-1]
    fp = sha1(root_cert_der).encode("hex")
    if unknown_root:
        output_file = os.path.join(
                FLAGS.output_dir, "unknown_roots", fp + ".der")
        open(output_file, "wb").write(root_cert_der)
    cert_output_dir = os.path.join(FLAGS.output_dir, "certs", fp)
    try:
        os.mkdir(cert_output_dir)
    except OSError:
        pass
    pem_chain = pem_cert_chain_for_cert(
            c,
            chain)
    if unknown_root:
        file_desc = "unk"
    else:
        file_desc = "xsig"
    open(os.path.join(cert_output_dir, cert_filename.replace(".der", "_%s_chain.pem" % file_desc)),
         "wb").write(pem_chain)


def calculate_certificate_hash(cert_filename):
    cert_der = open(os.path.join(FLAGS.certs_dir, cert_filename), "rb").read()
    c = cert.Certificate(cert_der)
    if c.is_expired():
        print 'Certificate expired:',cert_filename
        return None

    res = analyze_cert(c, cert_filename)
    ret_value = None

    if res.fingerprint_matched:
        h = hashlib.sha256()
        h.update(c.to_der())
        ret_value = h.digest()[0:FLAGS.hash_trim]
        if res.fingerprint_matches_other_root:
            # Cross-signed EV cert - store for future analysis
            write_interesting_chain(cert_filename, c, False)
    else:
        # Unknown root cert
        write_interesting_chain(cert_filename, c, True)

    return ret_value

def main():
    if os.path.exists(FLAGS.output_dir):
        os.rmdir(FLAGS.output_dir)
    os.mkdir(FLAGS.output_dir)
    os.mkdir(os.path.join(FLAGS.output_dir, "unknown_roots"))
    os.mkdir(os.path.join(FLAGS.output_dir, "certs"))

    clist = get_certificates_list(FLAGS.certs_dir)
    p = multiprocessing.Pool(processes=FLAGS.multi)
    calculated_hashes = p.map(calculate_certificate_hash, clist)
    p.close()
    p.join()
    print "Out of %d certificates %d did not chain to a known root" % (
            len(calculated_hashes), calculated_hashes.count(None))
    pickle.dump(calculated_hashes, open(FLAGS.output, "wb"))


if __name__ == '__main__':
    sys.argv = FLAGS(sys.argv)
    main()
