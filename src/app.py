import os, socket, sys
import p2p
from flask import Flask
from blockchain import Blockchain, load_chain_from_file, load_nodes_from_file
from api import register_routes
import config

app = Flask(__name__)

nodes = load_nodes_from_file()
chain = load_chain_from_file()
blockchain = Blockchain(nodes, chain)

# Determine HTTP port
http_port = int(sys.argv[1]) if len(sys.argv) > 1 else config.default_http_port
my_ip = os.getenv('MY_IP', socket.gethostbyname(socket.gethostname()))

# Start P2P with IP and port
p2p.start_discovery(my_ip, http_port, blockchain)

register_routes(app, blockchain)
blockchain.resolve_conflicts()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=http_port, threaded=True)
