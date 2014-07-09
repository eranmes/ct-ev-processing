#!/usr/bin/env python

import functools
import hashlib
import pickle
import os
import sys
from collections import defaultdict

import ev
import gflags

from ct.client import scanner
from ct.crypto import cert
from ct.crypto.asn1 import oid
from ct.proto import client_pb2

FLAGS = gflags.FLAGS

gflags.DEFINE_integer("multi", 1, "Number of cert parsing processes to use in "
                      "addition to the main process and the network process.")

gflags.DEFINE_string("output_directory", "ev_certs",
                     "Output directory for individual EV certificates.")



def ev_match(certificate, entry_type, extra_data, certificate_index):
    # Only generate whitelist for non-precertificates
    if entry_type != client_pb2.X509_ENTRY:
        return False
    if certificate.is_expired():
        return False
    try:
        for policy in certificate.policies():
            if policy['policyIdentifier'] in ev.EV_POLICIES:
                open(os.path.join(
                    FLAGS.output_directory,
                    "cert_%d.der" % certificate_index), "wb"
                     ).write(certificate.to_der())

                pickle.dump(
                    list(extra_data.certificate_chain),
                    open(os.path.join(
                        FLAGS.output_directory,
                        "cert_%d_extra_data.pickle" % certificate_index),
                         "wb"))
                return True
    except cert.CertificateError as e:
        pass
    return False


def run():
    if not os.path.exists(FLAGS.output_directory):
        os.mkdir(FLAGS.output_directory)
    res = scanner.scan_log(
        ev_match,
        "https://ct.googleapis.com/pilot", FLAGS.multi)
    print "Scanned %d, %d matched and %d failed strict or partial parsing" % (
        res.total, res.matches, res.errors)


if __name__ == "__main__":
    sys.argv = FLAGS(sys.argv)
    run()
