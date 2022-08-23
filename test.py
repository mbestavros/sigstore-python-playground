#!/usr/bin/env python
# -*- coding: utf-8 -*-
import base64
import hashlib
import merkle
import sigstore
import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from os.path import exists

def main():
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

    print(" --- SIGNING STEP --- ")

    artifact = "Sigstore is the future!!"

    upload_response = sigstore.sign_offline_and_upload(private_key, artifact)

    print("Rekor upload response:")
    print(json.dumps(json.loads(upload_response["response"].content), indent=4, sort_keys=True))

    print()
    print(" --- VERIFICATION STEP - HASH SEARCH --- ")

    artifact_hash = hashlib.sha256(artifact.encode()).hexdigest()

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

    print()
    print(" --- VERIFICATION STEP - INPUTS SEARCH --- ")

    artifact_signature = upload_response["signature"]
    fetch_inputs_response = sigstore.fetch_with_inputs(artifact_signature, public_key, artifact_hash)
    entries = json.loads(fetch_inputs_response.content)[0]
    print("Retrieved entries:")
    print(json.dumps(entries, indent=4, sort_keys=True))
    for entry in entries.keys():
        entry_encoded = entries[entry]['body']
        rekor_cert = json.loads(base64.b64decode(entry_encoded))['spec']['signature']['content']

        try:
            public_key.verify(base64.b64decode(rekor_cert), artifact.encode(), ec.ECDSA(hashes.SHA256()))
            print('Artifact signature verification against Rekor passed!')
        except:
            print('Artifact signature verification against Rekor failed!')

        try:
            merkle.verify_merkle_inclusion(entries[entry])
            print("Inclusion proof verified!")
        except merkle.InvalidInclusionProofError as e:
            print(e)

if __name__ == "__main__":
    main()
