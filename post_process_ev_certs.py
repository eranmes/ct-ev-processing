#!/usr/bin/env python

from collections import namedtuple, defaultdict
import hashlib
import multiprocessing
import pickle
import Queue
import os
import re
import sys

import ev
from ct.crypto import cert
from ct.crypto import pem

import gflags

FLAGS = gflags.FLAGS

gflags.DEFINE_string("base_path", ".", "Base directory containing all EV certs")
gflags.DEFINE_string("output_chains_path", "ev_chains", "Output directory for "
                     "interesting EV chains.")
gflags.DEFINE_string("output_roots_path", "unknown_roots", "Output directory "
                     "for unknown roots.")

def find_matching_policy(c):
  for policy in c.policies():
    if policy['policyIdentifier'] in ev.EV_POLICIES:
      return policy['policyIdentifier']
  return None


def sha1(data):
  s = hashlib.sha1()
  s.update(data)
  return s.digest()


ChainAnalysisResult = namedtuple("ChainAnalysisResult", [
  "fingerprint_matched", "fingerprint_matches_other_root",
  "all_fingerprints", "chain_pem", "root_cert_der"])


def analyze_cert(c, cert_index):
  chain_file_name = 'cert_%d_extra_data.pickle' % cert_index
  cert_chain_der = pickle.load(
      open(os.path.join(FLAGS.base_path, chain_file_name), "rb"))
  matching_policy = find_matching_policy(c)
  assert matching_policy
  output_pem = c.to_pem() + '\n'
  chain_fingerprints = [sha1(c.to_der())]
  for chained_cert_der in cert_chain_der:
    chain_fingerprints.append(sha1(chained_cert_der))
    output_pem += pem.to_pem(chained_cert_der, "CERTIFICATE") + '\n'

  fingerprint_matched = any([fp in ev.EV_POLICIES[matching_policy]
                             for fp in chain_fingerprints])
  root_may_be_cross_signed = any(
      [fp in ev.EV_ROOTS.keys() for fp in chain_fingerprints])

  return ChainAnalysisResult(
      fingerprint_matched,
      root_may_be_cross_signed,
      chain_fingerprints, output_pem,
      chained_cert_der)


QueuedCertificate = namedtuple("QueuedCertificate", ["index", "der"])

def enqueue_certificates(base_dir, output_queue, num_processes, num_read):
  file_matcher = re.compile('cert_([0-9]+)\.der')
  local_num_read = 0
  for f in os.listdir(base_dir):
    m = file_matcher.match(f)
    if m:
      local_num_read += 1
      cert_index = int(m.group(1))
      cert_der = open(os.path.join(base_dir, f), 'rb').read()
      output_queue.put(QueuedCertificate(cert_index, cert_der))
  num_read.value = local_num_read
  print "Read a total of %d certificates." % local_num_read
  for _ in range(num_processes):
    output_queue.put(None)


UnknownRootCertificate = namedtuple("UnknownRootCertificate",
                                    ["fingerprint", "der"])
OutputCertificate = namedtuple("OutputCertificate",
                               ["output_path", "output_file", "pem"])

def handle_certificates(certs_queue, output_queue, num_expired,
                        num_fp_mismatch, num_fp_other_root):
  local_num_expired = 0
  local_num_fingerprint_mismatch = 0
  local_num_fp_other_root = 0
  queued_cert = certs_queue.get(True)
  while queued_cert:
    c = cert.Certificate(queued_cert.der)
    if not c.is_expired():
      res = analyze_cert(c, queued_cert.index)
      output_file = "chain_%d.pem" % (queued_cert.index)
      last_fp = res.all_fingerprints[-1]
      if not res.fingerprint_matched:
        local_num_fingerprint_mismatch += 1
        if res.fingerprint_matches_other_root:
          output_file = "chain_%d_xsigned.pem" % (queued_cert.index)
          local_num_fp_other_root += 1
        else:
          output_file = "chain_%d_unk.pem" % (queued_cert.index)
          output_queue.put(
              UnknownRootCertificate(last_fp, res.root_cert_der))
      base_path = os.path.join(FLAGS.output_chains_path, last_fp.encode("hex"))
      output_queue.put(OutputCertificate(base_path, output_file, res.chain_pem))
    else:
      local_num_expired += 1
    queued_cert = certs_queue.get(True)
  print "None queue item, returning."

  with num_expired.get_lock():
    num_expired.value += local_num_expired
  with num_fp_mismatch.get_lock():
    num_fp_mismatch.value += local_num_fingerprint_mismatch
  with num_fp_other_root.get_lock():
    num_fp_other_root.value += local_num_fp_other_root
  output_queue.put(None)


def main():
  certs_queue = multiprocessing.Queue(10000)
  num_processes = 32
  if not os.path.exists(FLAGS.output_chains_path):
    os.mkdir(FLAGS.output_chains_path)

  total_certs = multiprocessing.Value('i', 0, lock=True)
  reader_process = multiprocessing.Process(
      target=enqueue_certificates,
      args=(FLAGS.base_path, certs_queue, num_processes, total_certs))

  reader_process.start()

  certs_expired = multiprocessing.Value('i', 0, lock=True)
  certs_fp_mismatch = multiprocessing.Value('i', 0, lock=True)
  certs_fp_other_root = multiprocessing.Value('i', 0, lock=True)
  output_queue = multiprocessing.Queue(10000)
  workers = [
      multiprocessing.Process(
          target=handle_certificates,
          args=(certs_queue, output_queue, certs_expired, certs_fp_mismatch,
                certs_fp_other_root))
      for _ in range(num_processes)]

  for w in workers:
    w.start()

  hash_to_count = defaultdict(int)
  hash_to_certificate = {}
  try:
    num_finished = 0
    while num_finished < num_processes:
      output = output_queue.get(True)
      if output:
        if isinstance(output, UnknownRootCertificate):
          hash_to_count[output.fingerprint] += 1
          hash_to_certificate[output.fingerprint] = output.der
        elif isinstance(output, OutputCertificate):
          if not os.path.exists(output.output_path):
            os.mkdir(output.output_path)
          open(os.path.join(output.output_path, output.output_file),
               "wb").write(output.pem)
        else:
          print "Unknown output from worker: %s" % output
      else:
        num_finished += 1
    reader_process.join()

    for w in workers:
      w.join()
  # Do not hang the interpreter upon ^C.
  except (KeyboardInterrupt, SystemExit):
    reader_process.terminate()
    for w in workers:
      w.terminate()
    raise

  print "Final results:"
  print ("Processed a total of %d certificates, out of which %d expired "
         "and %d had a mismatching root sha-1 fingerprint (but %d may be cross signed)." % (
             total_certs.value, certs_expired.value, certs_fp_mismatch.value,
             certs_fp_other_root.value))
  print "Interesting roots: Total of %d, breakdown by fingerprint:" % len(hash_to_count)
  for fp in hash_to_count:
    fp_hash = fp.encode("hex")
    fp_count = hash_to_count[fp]
    print "  %s: %d" % (fp_hash , fp_count)
    with open(os.path.join(
        FLAGS.output_roots_path, "%s_%d.der" % (fp_hash, fp_count)), "wb") as f:
      f.write(hash_to_certificate[fp])


if __name__ == '__main__':
  main()
