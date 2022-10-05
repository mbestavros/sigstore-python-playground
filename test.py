#!/usr/bin/env python
# -*- coding: utf-8 -*-
from typing import cast

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
