#!/usr/bin/env python
# -*- coding: utf-8 -*-
from typing import cast

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from os.path import exists

from sigstore._internal.oidc.issuer import Issuer
from sigstore._internal.oidc.oauth import (
    DEFAULT_OAUTH_ISSUER,
    STAGING_OAUTH_ISSUER,
    get_identity_token,
)
from sigstore._sign import Signer
from sigstore._verify import (
    CertificateVerificationFailure,
    VerificationFailure,
    Verifier,
)

def main():
    # --- CREATE KEYPAIR (for manual signing if needed) ---

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

    signer = Signer.staging()
    #signer = Signer.production()

    issuer = Issuer(STAGING_OAUTH_ISSUER) # use DEFAULT_OAUTH_ISSUER if using production

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

    artifact_signature = result.b64_signature
    artifact_certificate = result.cert_pem.encode()

    print(" --- VERIFICATION STEP --- ")

    verifier = Verifier.staging()
    #verifier = Verifier.production()

    result = verifier.verify(
        input_=artifact,
        certificate=artifact_certificate,
        signature=artifact_signature
    )

    if result:
        print(f"OK")
    else:
        result = cast(VerificationFailure, result)
        print(f"FAIL")
        print(f"Failure reason: {result.reason}")


if __name__ == "__main__":
    main()
