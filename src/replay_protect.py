import time
import uuid
from functools import wraps
from flask import request, jsonify

WINDOW=60
seen_nounces = {}

def cleanup_nounces():
    now = time.time()
    for n, exp in list(seen_nonces.items()):
        if exp < now:
            del seen_nonces[n]

def replay_protect(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        cleanup_nonces()
        data= request.get_json() or {}
        ts = data.get('timestamp')
        nounce = data.get('nonce')
        if not isinstance(ts, (int, float)) or not isinstance(nonce, str):
            return jsonify({'error': 'timestamp+nonce required'}), 400
        now = time.time()
        if abs(now - ts) > WINDOW:
            return jsonify({'error': 'timestamp out of window'}), 400
        if nonce in seen_nonces:
            return jsonify({'error': 'replayed request'}), 400
        seen_nonces[nonce] = now + WINDOW
        return f(*args, *kwargs)
    return wrapper
