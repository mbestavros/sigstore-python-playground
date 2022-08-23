#!/usr/bin/env python
# -*- coding: utf-8 -*-
import base64
import getopt
import merkle
import sigstore
import sys
import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from os.path import exists

def main(argv):

    # --- CREATE KEYS ---

    if not exists("private.key"):
        print("Private key not found, creating a new one...")
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend()).private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open("private.key", 'wb') as pem_out:
            pem_out.write(private_key)

    with open("private.key", 'rb') as pem_in:
        pemlines = pem_in.read()
    private_key = load_pem_private_key(pemlines, None, default_backend())
    public_key = private_key.public_key()

    # Write public key to a file
    with open("public.pem", "wb") as pem_out:
        pem_out.write(public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))

    # get paths
    allowlist = None
    try:
        opts, args = getopt.getopt(argv,"ha:",["allowlistfile="])
    except getopt.GetoptError:
        print('importer.py -a <allowlist>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print("test.py -a <allowlistfile>")
            sys.exit()
        elif opt in ("-a", "--allowlistfile"):
            allowlist = arg

    print(" --- SIGNING STEP --- ")

    with open(allowlist, "r") as f:
        alist_raw = f.read()

    tlog_policy = {}
    for line in alist_raw.splitlines()[:10]:
        line = line.strip()
        if len(line) == 0:
            continue

        pieces = line.split(None, 1)
        if not len(pieces) == 2:
            print("Line in Allowlist does not consist of hash and file path: %s", line)
            continue

        (checksum_hash, path) = pieces

        tlog_policy[path] = checksum_hash

        print(f"Uploading path: {path}")

        with open(path, "rb") as artifact:
            upload_response = sigstore.sign_offline_and_upload(private_key, artifact)

    print()
    print(" --- VERIFICATION STEP - HASH SEARCH --- ")

    for artifact_hash in tlog_policy:

        search_response = sigstore.search(hash=artifact_hash)

        uuids = json.loads(search_response.content)

        print('Found UUIDs matching provided artifact hash. Verifying...')

        for uuid in uuids:

            fetch_uuid_response = sigstore.fetch_with_uuid(uuid=uuid)

            entries = json.loads(fetch_uuid_response.content)
            for key in entries.keys():
                entry = entries[key]
            encoded_rekord = entry["body"]
            rekor_cert = json.loads(base64.b64decode(encoded_rekord))['spec']['signature']['content']

            try:
                public_key.verify(base64.b64decode(rekor_cert), artifact.encode(), ec.ECDSA(hashes.SHA256()))
                print(f'{uuid}: Signature validation: PASS')
            except:
                print(f'{uuid}: Signature validation: FAIL')

            try:
                merkle.verify_merkle_inclusion(entry)
                print("Inclusion proof verified!")
            except merkle.InvalidInclusionProofError as e:
                print(e)


if __name__ == "__main__":
    main(sys.argv[1:])
