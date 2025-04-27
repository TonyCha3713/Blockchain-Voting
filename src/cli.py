#!/usr/bin/python3
import argparse
import json
import getpass
import requests
import config
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption
from cryptography.hazmat.backends import default_backend


def pretty_print(resp):
    try:
        print(json.dumps(resp.json(), indent=2))
    except Exception:
        print(resp.text)

# Generate keypair without registration
def cmd_genkey(args):
    private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
    public_key = private_key.public_key()

    passphrase = args.passphrase or getpass.getpass('Enter passphrase (empty for none): ')
    enc_algo = BestAvailableEncryption(passphrase.encode()) if passphrase else serialization.NoEncryption()

    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc_algo
    )
    with open(config.PRIVATE_KEY, 'wb') as f:
        f.write(priv_bytes)

    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(config.PUBLIC_KEY, 'wb') as f:
        f.write(pub_pem)

    print(f"Private key written to {config.PRIVATE_KEY}")
    print(f"Public key written to {config.PUBLIC_KEY}")

# Register existing public key and IP with network
def cmd_register(args):
    with open(config.PUBLIC_KEY, 'rb') as f:
        pub_pem = f.read()
    public_key = serialization.load_pem_public_key(pub_pem, backend=default_backend())
    pub_hex = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    ).hex()

    resp = requests.post(
        f"{args.server}/register_node",
        json={'public_key': pub_hex, 'ip': args.ip, 'port': args.port}
    )
    print('Response:')
    pretty_print(resp)

# Cast vote using existing keypair and public key file as voter ID
def cmd_vote(args):
    passphrase = args.passphrase or getpass.getpass('Enter passphrase: ')
    # Load and decrypt private key
    with open(config.PRIVATE_KEY, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=passphrase.encode() if passphrase else None,
            backend=default_backend()
        )
    # Derive public key hex from public key file
    with open(config.PUBLIC_KEY, 'rb') as f:
        pub_pem = f.read()
    public_key = serialization.load_pem_public_key(pub_pem, backend=default_backend())
    pub_hex = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    ).hex()

    signature = private_key.sign(args.candidate.encode(), ec.ECDSA(hashes.SHA256()))
    sig_hex = signature.hex()

    resp = requests.post(
        f"{args.server}/vote",
        json={
            'public_key': pub_hex,
            'candidate': args.candidate,
            'signature': sig_hex
        }
    )
    print('Response:')
    pretty_print(resp)

# Mine pending votes
def cmd_mine(args):
    resp = requests.post(f"{args.server}/mine")
    print('Response:')
    pretty_print(resp)

def cmd_myvote(args):
    with open(config.PUBLIC_KEY, 'rb') as f:
        pub_pem = f.read()
    public_key = serialization.load_pem_public_key(pub_pem, backend=default_backend())
    pub_hex = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    ).hex()
    resp = requests.post(f"{args.server}/myvote", json={'public_key': pub_hex})
    print('Response:')
    pretty_print(resp)


# CLI entrypoint
def main():
    parser = argparse.ArgumentParser('Blockchain CLI')
    parser.add_argument('--server', default='http://localhost:5000')
    parser.add_argument('--passphrase', help='Passphrase for key encryption/decryption')
    sub = parser.add_subparsers(dest='command', required=True)

    g = sub.add_parser('genkey', help='Generate keypair')
    g.set_defaults(func=cmd_genkey)

    r = sub.add_parser('register', help='Register public key and IP')
    r.add_argument('--ip', required=True, help='Your IP address')
    r.add_argument('--port', required=True, help='Your port')
    r.set_defaults(func=cmd_register)

    v = sub.add_parser('vote', help='Cast vote using key files')
    v.add_argument('--candidate', required=True)
    v.set_defaults(func=cmd_vote)

    m = sub.add_parser('mine', help='Mine votes')
    m.set_defaults(func=cmd_mine)

    n = sub.add_parser('myvote', help='Display my vote')
    n.set_defaults(func=cmd_myvote)

    args = parser.parse_args()
    args.func(args)

if __name__ == '__main__':
    main()

