import base64
import hashlib
import requests
import simplejson as json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

REKOR_URL = "https://rekor.sigstore.dev"

REKOR_API_HEADERS = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
}

def sign_offline_and_upload(private_key, artifact):
    public_key = private_key.public_key()

    # Sign artifact
    artifact_signature = private_key.sign(
        artifact,
        ec.ECDSA(hashes.SHA256())
    )

    # Test signature
    try:
        public_key.verify(artifact_signature, artifact, ec.ECDSA(hashes.SHA256()))
        print('Artifact signature local verification passed.')
    except:
        print('Artifact signature local verification failed!')

    # Prepare inputs
    artifact_signature_b64 = base64.b64encode(artifact_signature)
    artifact_hash = hashlib.sha256(artifact).hexdigest()
    pub_b64 = _encode_pubkey(public_key)

    # Prepare upload payload
    payload_json = {
        "kind": "hashedrekord",
        "apiVersion": "0.0.1",
        "spec": {
            "signature": {
                "content": artifact_signature_b64,
                "publicKey": {
                    "content": pub_b64
                }
            },
            "data": {
                "hash": {
                    "algorithm": "sha256",
                    "value": artifact_hash
                }
            }
        }
    }
    payload = json.dumps(payload_json)

    return {
        "signature": artifact_signature,
        "response": requests.post(f"{REKOR_URL}/api/v1/log/entries", data=payload,  headers=REKOR_API_HEADERS),
    }

def search(email=None, pubkey=None, hash=None):
    if pubkey is not None:
        pubkey = _encode_pubkey(pubkey)
    rekor_payload_search = {
        "email": email,
        "publicKey": pubkey,
        "hash": f"sha256:{hash}",
    }
    payload = json.dumps(rekor_payload_search)

    return requests.post(f"{REKOR_URL}/api/v1/index/retrieve", data=payload,  headers=REKOR_API_HEADERS)

def fetch_with_uuid(uuid):
    return requests.get(f"{REKOR_URL}/api/v1/log/entries/{uuid}",  headers=REKOR_API_HEADERS)

def fetch_with_inputs(signature, pubkey, hash):
    artifact_signature_b64 = base64.b64encode(signature)
    pub_b64 = _encode_pubkey(pubkey)

    rekor_payload_search = {
        "entries": [
            {
                "kind": "hashedrekord",
                "apiVersion": "0.0.1",
                "spec": {
                    "signature": {
                        "content": artifact_signature_b64,
                        "publicKey": {
                            "content": pub_b64
                        }
                    },
                    "data": {
                        "hash": {
                            "algorithm": "sha256",
                            "value": hash
                        }
                    }
                }
            }
        ],
    }
    payload = json.dumps(rekor_payload_search)

    return requests.post(f"{REKOR_URL}/api/v1/log/entries/retrieve", data=payload,  headers=REKOR_API_HEADERS)

def _encode_pubkey(pubkey):
    # serializing into PEM
    rsa_pem = pubkey.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    pub_pem = rsa_pem.decode("utf-8").replace("\\n", "")
    pbytes: bytes = bytes(pub_pem, encoding="raw_unicode_escape")
    return base64.b64encode(pbytes).decode("utf8")
