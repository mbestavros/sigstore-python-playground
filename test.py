#!/usr/bin/env python
# -*- coding: utf-8 -*-
import base64
import hashlib
import json
import sigstore._sign as sign
import sigstore._verify as verify

from sigstore._internal.oidc.issuer import Issuer
from sigstore._internal.oidc.oauth import (
    DEFAULT_OAUTH_ISSUER,
    STAGING_OAUTH_ISSUER,
    get_identity_token,
)


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

    signer = sign.Signer.staging()

    issuer = Issuer(STAGING_OAUTH_ISSUER)

    identity_token = get_identity_token(
        "sigstore",
        "", # oidc client secret
        issuer,
    )

    artifact = b"Sigstore is the future!"

    result = signer.sign(
        input_=artifact,
        identity_token=identity_token
    )

    print("Using ephemeral certificate:")
    print(result.cert_pem)

    print(f"Transparency log entry created at index: {result.log_entry.log_index}")



if __name__ == "__main__":
    main()
