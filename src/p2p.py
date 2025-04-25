import socket
import struct
import threading
import time
import json
import config
from blockchain import save_nodes_to_file

# Multicast settings
GRP = config.MULTICAST_GROUP
PORT = config.MULTICAST_PORT
DISC_INTERVAL = config.DISCOVERY_INTERVAL

def start_discovery(my_ip, http_port, blockchain):
    def announce():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, struct.pack('b', 1))
        # Now send both IP and port as JSON
        msg = json.dumps({'ip': my_ip, 'port': http_port}).encode()
        while True:
            sock.sendto(msg, (GRP, PORT))
            time.sleep(DISC_INTERVAL)

    def listen():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', PORT))
        mreq = struct.pack('4sl', socket.inet_aton(GRP), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        while True:
            data, _ = sock.recvfrom(1024)
            try:
                info = json.loads(data.decode())
                ip = info['ip']
                port = info['port']
            except (ValueError, KeyError):
                continue

            if ip == my_ip and port == http_port:
                continue

            # avoid duplicates
            if not any(n.get('ip') == ip and n.get('port') == port for n in blockchain.nodes):
                blockchain.nodes.append({
                    'id': None,
                    'ip': ip,
                    'port': port,
                    'voted': False,
                    'voted_at': None
                })
                save_nodes_to_file(blockchain.nodes)

    threading.Thread(target=announce, daemon=True).start()
    threading.Thread(target=listen, daemon=True).start()
