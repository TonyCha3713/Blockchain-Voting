from flask import request, jsonify, Response
import time, requests, json
from blockchain import save_nodes_to_file, save_chain_to_file, verify_vote_signature 
import config
from replay_protect import replay_protect


def broadcast_post(path, payload, blockchain, ip, port):
    with blockchain.nodes_lock:
        peers = list(blockchain.nodes)
    for peer in peers:
        if peer['ip'] == ip and peer['port'] == port:
            continue;
        try:
            requests.post(f"http://{peer['ip']}:{peer['port']}{path}", json=payload, timeout=2)
        except:
            continue

def broadcast_get(path, blockchain, ip, port):
    with blockchain.nodes_lock:
        peers = list(blockchain.nodes)
    for peer in peers:
        if peer['ip'] == ip and peer['port'] == port:
            continue;
        try:
            requests.get(f"http://{peer['ip']}:{peer['port']}{path}", timeout=2)
        except:
            continue

def register_routes(app, blockchain):
    @app.route('/chain', methods=['GET'])
    def get_chain():
        payload = {
            'length': len(blockchain.chain),
            'chain': [block.__dict__ for block in blockchain.chain]
        }
        return jsonify(payload), 200

    @app.route('/nodes', methods=['GET'])
    def get_nodes():
        return jsonify({'nodes': list(blockchain.nodes)}), 200

    @app.route('/candidates', methods=['GET'])
    def get_candidates():
        return jsonify({'candidates': config.CANDIDATES}), 200

    @app.route('/register_node', methods=['POST'])
    def register_node():
        data = request.get_json() or {}
        public_key, ip, port = data.get('public_key'), data.get('ip'), int(data.get('port'))
        if not ip or not public_key or not port:
            return jsonify({'error': 'Missing values'}), 400
        with blockchain.nodes_lock:
            node = next((n for n in blockchain.nodes if n.get('ip') == ip and n.get('port') == port), None)
            if node:
                node['port'] = port
                if node.get('id') and node['id'] != public_key:
                    return jsonify({'error': 'IP already registered with different key'}), 409
                node['id'] = public_key
            else:
                node = {'id': public_key, 'ip': ip, 'port': port, 'voted': False, 'voted_at': None}
                blockchain.nodes.append(node)
            save_nodes_to_file(blockchain.nodes)
        broadcast_post('/peers/register', {'public_key': public_key, 'ip': ip, 'port': port}, blockchain, ip, port)
        return jsonify({'message': 'Node registered'}), 201

    @app.route('/peers/register', methods=['POST'])
    def peer_register():
        data = request.get_json() or {}
        public_key, ip, port = data.get('public_key'), data.get('ip'), data.get('port')
        if not public_key or not ip or not port:
            return jsonify({'error': 'Missing values'}), 400
        
        with blockchain.nodes_lock:
            node = next((n for n in blockchain.nodes if n.get('ip') == ip and n.get('port') == port), None)
            if node:
                node['port'] = port
                if not node.get('id'):
                    node['id'] = public_key
                    save_nodes_to_file(blockchain.nodes)
                return jsonify({'message': 'Peer updated'}), 200
            blockchain.nodes.append({'id': public_key, 'ip': ip, 'port': port, 'voted': False, 'voted_at': None})
            save_nodes_to_file(blockchain.nodes)
        return jsonify({'message': 'Peer added'}), 201


    @app.route('/vote', methods=['POST'])
    def vote():
        data = request.get_json() or {}
        public_key, candidate, signature = data.get('public_key'), data.get('candidate'), data.get('signature')
        if not public_key or not candidate or not signature:
            return jsonify({'error': 'Missing values'}), 400
        if candidate not in config.CANDIDATES:
            return jsonify({'error': 'Invalid candidate'}), 400
        with blockchain.nodes_lock:
            node = next((n for n in blockchain.nodes if n['id'] == public_key), None)
            if not node: return jsonify({'error': 'Node not registered'}), 403
            if node['voted']: return jsonify({'error': 'Already voted'}), 403
            if not verify_vote_signature(public_key, candidate, signature):
                return jsonify({'error': 'Invalid signature'}), 403
            ip = node['ip']
            port = node['port']
            node['voted'] = True
            node['voted_at'] = time.time()
            save_nodes_to_file(blockchain.nodes)
        blockchain.add_vote({'public_key': public_key, 'candidate': candidate, 'signature': signature})
        broadcast_post('/transactions/new', {'public_key':public_key, 'candidate': candidate, 'signature': signature}, blockchain, ip, port)
        return jsonify({'message': 'Vote queued'}), 201

    @app.route('/transactions/new', methods=['POST'])
    def new_transaction():
        data = request.get_json() or {}
        public_key, candidate, signature = data.get('public_key'), data.get('candidate'), data.get('signature')
        if not public_key or not candidate or not signature:
            return jsonify({'error': 'Missing values'}), 400
        with blockchain.nodes_lock:
            node = next((n for n in blockchain.nodes if n['id'] == public_key), None)
            if not node: return jsonify({'error': 'Node not registered'}), 403
            if node['voted']: return jsonify({'error': 'Already voted'}), 403
            if not verify_vote_signature(public_key, candidate, signature):
                return jsonify({'error': 'Invalid signature'}), 403
            node['voted'] = True
            node['voted_at'] = time.time()
            save_nodes_to_file(blockchain.nodes)
        blockchain.add_vote({'public_key': public_key, 'candidate': candidate, 'signature': signature})
        return jsonify({'message': 'Transaction added'}), 201

    @app.route('/pending-votes', methods=['GET'])
    def pending_votes():
        return jsonify({'pending-votes': blockchain.pending_votes}), 200

    @app.route('/myvote', methods=['POST'])
    def my_vote():
        data = request.get_json() or {}
        public_key = data.get('public_key')
        if not public_key:
            return jsonify({'error': 'Missing public_key'}), 400
        for block in blockchain.chain:
            for vote in block.votes:
                if vote['public_key'] == public_key:
                    return jsonify({'my_vote': vote}), 200
        return jsonify({'my_vote': None}), 200

    @app.route('/mine', methods=['POST'])
    @replay_protect
    def mine():
        block = blockchain.mine_block()
        if not block:
            return jsonify({'message': 'No votes to mine'}), 400

        block_data = block.__dict__
        with blockchain.nodes_lock:
            peers = list(blockchain.nodes)
        acks = 0
        total = len(blockchain.nodes)
        for peer in peers:
            try:
                res = requests.post(f"http://{peer['ip']}:{peer['port']}/block/prepare", json=block_data, timeout=2)
                if res.status_code == 200:
                    acks += 1
            except:
                pass

        if acks <= total * config.ACKS:
            blockchain.chain.pop()
            save_chain_to_file(blockchain.chain)
            return jsonify({'error': 'Consensus failed'}), 500

        for peer in peers:
            try:
                res = requests.post(f"http://{peer['ip']}:{peer['port']}/block/commit", json=block_data, timeout=2)
            except:
                pass

        save_chain_to_file(blockchain.chain)
        return jsonify(block_data), 201

    @app.route('/block/prepare', methods=['POST'])
    def prepare_block():
        data = request.get_json()
        from blockchain import Block
        candidate = Block(**data)
        if candidate.compute_hash() != data['hash'] or not data['hash'].startswith('0' * blockchain.difficulty):
            return jsonify({'error': 'Invalid block'}), 400
        return jsonify({'ack': True}), 200

    @app.route('/block/commit', methods=['POST'])
    def commit_block():
        data = request.get_json()
        block_hash = data.get('hash')
        block_index = data.get('index')
        if any(b.hash == block_hash for b in blockchain.chain) or (blockchain.chain and blockchain.chain[-1].index == block_index):
            return jsonify({'Already commited': True}), 200
        from blockchain import Block
        new_block = Block(**data)
        blockchain.chain.append(new_block)
        save_chain_to_file(blockchain.chain)
        blockchain.pending_votes = []
        return jsonify({'commited': True}), 201

    @app.route('/results', methods=['GET'])
    def get_results():
        tally = {c: 0 for c in config.CANDIDATES}
        for block in blockchain.chain:
            for vote in block.votes:
                cand = vote['candidate']
                if cand in tally:
                    tally[cand] += 1
        return jsonify({'results': tally}), 200
    
    @app.route('/metrics', methods=['GET'])
    def metrics():
        with blockchain.nodes_lock:
            peer_count = len(blockchain.nodes)
        pending_votes = len(blockchain.pending_votes)
        chain_length = len(blockchain.chain)
        lines = [
            '# HELP blockchain_peer_count Number of known peers',
            '# TYPE blockchain_peer_count gauge',
            f'blockchain_peer_count {peer_count}',
            '# HELP blockchain_pending_votes Number of votes waiting to be mined',
            '# TYPE blockchain_pending_votes gauge',
            f'blockchain_pending_votes {pending_votes}',
            '# HELP blockchain_chain_length Number of blocks in the chain',
            '# TYPE blockchain_chain_length gauge',
            f'blockchain_chain_length {chain_length}',
        ]
        return Response('\n'.join(lines) + '\n', mimetype='text/plain')

    @app.route('/healthz', methods=['GET'])
    def healthz():
        try:
            # Basic self‐check: ensure we can read our files
            _ = blockchain.chain  # in-memory
            with blockchain.nodes_lock:
                _ = list(blockchain.nodes)
            return jsonify({'status': 'ok'}), 200
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)}), 500            

    @app.route('/sync', methods=['GET'])
    def sync():
        blockchain.resolve_conflicts()
        save_chain_to_file(blockchain.chain)
        with blockchain.nodes_lock:
            nodes_list = list(blockchain.nodes)
        save_nodes_to_file(nodes_list)
        return jsonify({
            'message': 'Chain replaced if needed',
            'chain': [block.__dict__ for block in blockchain.chain]
        }), 200
    @app.route('/help', methods=['GET'])
    def help():
        routes = {
            '/help':        'GET — list all endpoints and what they do',
            '/chain':       'GET — return the full blockchain',
            '/nodes':       'GET — return the list of known peers',
            '/candidates':  'GET — return the list of valid candidates',
            '/register_node':   'POST — register (or update) a node; JSON {public_key, ip, port}',
            '/peers/register':  'POST — internal P2P hook for peer announce',
            '/vote':        'POST — cast a vote; JSON {public_key, candidate, signature}',
            '/transactions/new': 'POST — internal hook to accept a peer’s vote',
            '/pending-votes':    'GET — list all votes waiting to be mined',
            '/myvote':      'POST — return your own vote; multipart form “pubfile” or JSON {public_key}',
            '/mine':        'POST — mine a block via two-phase prepare/commit',
            '/block/prepare':   'POST — internal prepare phase; validate a candidate block',
            '/block/commit':    'POST — internal commit phase; append a prepared block',
            '/sync':        'GET — reconcile chain & peer list with the network',
            '/results':     'GET — return vote tallies by candidate',
            '/metrics':     'GET — Prometheus-style metrics (peer count, queue size, chain length)',
            '/healthz':     'GET — simple liveness/readiness check'
        }
        return jsonify(routes), 200
