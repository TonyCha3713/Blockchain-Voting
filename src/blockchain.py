import hashlib
import json
import time
import os
import requests
import threading
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import config

class Block:
    def __init__ (self, index, timestamp, votes, prev_hash, proof=0, hash=None): 
        self.index = index
        self.timestamp = timestamp
        self.votes = votes
        self.prev_hash = prev_hash
        self.proof = proof
        self.hash = hash or self.compute_hash()

    def compute_hash(self):
        block_string = json.dumps({
            'index': self.index,
            'timestamp' : self.timestamp,
            'votes': self.votes,
            'prev_hash': self.prev_hash,
            'proof': self.proof,
        }, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()


class Blockchain:
    def __init__(self, nodes=None, chain=None):
        self.nodes_lock = threading.Lock()
        self.nodes = nodes if nodes else []
        self.pending_votes = []
        self.difficulty = config.DIFFICULTY
        self.chain = chain if chain else [self.create_genesis_block()]

    def create_genesis_block(self):
        return Block(0, time.time(), [], 0)

    def get_last_block(self):
        return self.chain[-1]

    def add_vote(self, vote):
        self.pending_votes.append(vote)
    
    def mine_block(self):
        if not self.pending_votes:
            return None

        last = self.get_last_block()
        new_block = Block(
            index = last.index + 1,
            timestamp = time.time(),
            votes = self.pending_votes,
            prev_hash = last.hash
        )

        while not new_block.hash.startswith("0"*self.difficulty):
            new_block.proof += 1
            new_block.hash = new_block.compute_hash()

        self.chain.append(new_block)
        self.pending_votes = []
        save_chain_to_file(self.chain)
        return new_block
        
    def valid_chain(self, chain):
        for i in range (1, len(chain)):
            prev = chain[i - 1]
            curr = chain[i]
            if curr['prev_hash'] != prev['hash']:
                return False
            if not curr['hash'].startswith("0"*self.difficulty):
                return False
            block_obj = Block(**curr)
            if block_obj.compute_hash() != curr['hash']:
                return False

        return True

    def resolve_conflicts(self):
        longest_chain = self.chain
        longest_nodes = self.nodes
        for node in self.nodes:
            try:
                ip, port = node['ip'], node['port']
                res = requests.get(f'http://{ip}:{port}/chain')
                peer_chain = res.json().get('chain')
                if self.valid_chain(peer_chain) and len(peer_chain) > len(longest_chain):
                    longest_chain = [Block(**block) for block in peer_chain]
                    nodes_res = requests.get(f'http://{ip}:{port}/nodes')
                    peer_nodes = nodes_res.json().get('nodes', [])
                    longest_nodes = peer_nodes
            except:
                continue
        self.chain = longest_chain
        self.nodes = longest_nodes
        save_chain_to_file(self.chain)
        save_nodes_to_file(self.nodes)

def verify_vote_signature(public_key_hex, candidate, signature_hex):
    public_bytes = bytes.fromhex(public_key_hex)
    public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), public_bytes)
    signature = bytes.fromhex(signature_hex)
    try:
        public_key.verify(signature, candidate.encode(), ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False

def save_chain_to_file(chain):
    with open(config.BLOCKCHAIN_FILE, 'w') as f:
        json.dump([block.__dict__ for block in chain], f, indent=4)

def load_chain_from_file():
    if os.path.exists(config.BLOCKCHAIN_FILE):
        with open(config.BLOCKCHAIN_FILE, 'r') as f:
            return [Block(**block) for block in json.load(f)]
    return None

def save_nodes_to_file(nodes):
    with open(config.NODES_FILE, 'w') as f:
        json.dump(nodes, f, indent=4)

def load_nodes_from_file():
    if os.path.exists(config.NODES_FILE):
        with open(config.NODES_FILE, 'r') as f:
            return json.load(f)
    return []
