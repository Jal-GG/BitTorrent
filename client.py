import bencodepy
import requests
import socket
import random
import hashlib
import struct
import os
from urllib.parse import urlparse, urlencode

# --- Step 1: Parse .torrent file ---
def parse_torrent(torrent_path):
    with open(torrent_path, 'rb') as f:
        torrent = bencodepy.decode(f.read())
    info = torrent[b'info']
    info_hash = hashlib.sha1(bencodepy.encode(info)).digest()
    announce = torrent[b'announce'].decode()
    piece_length = info[b'piece length']
    pieces = info[b'pieces']
    length = info[b'length']
    name = info[b'name'].decode()
    return {
        'announce': announce,
        'info_hash': info_hash,
        'piece_length': piece_length,
        'pieces': pieces,
        'length': length,
        'name': name
    }

# --- Step 2: Contact tracker ---
def get_peers(meta, peer_id, port=6881):
    params = {
        'info_hash': meta['info_hash'],
        'peer_id': peer_id,
        'port': port,
        'uploaded': 0,
        'downloaded': 0,
        'left': meta['length'],
        'compact': 1,
        'event': 'started'
    }
    url = meta['announce'] + '?' + urlencode(params, quote_via=lambda x, *_: x)
    # info_hash and peer_id must be bytes, not urlencoded
    url = url.replace('info_hash=' + str(meta['info_hash']), 'info_hash=' + requests.utils.quote(meta['info_hash'], safe=''))
    url = url.replace('peer_id=' + str(peer_id), 'peer_id=' + requests.utils.quote(peer_id, safe=''))
    r = requests.get(url, timeout=10)
    tracker = bencodepy.decode(r.content)
    peers = tracker[b'peers']
    # peers is a binary string of 6-byte entries (4 bytes IP, 2 bytes port)
    peer_list = []
    for i in range(0, len(peers), 6):
        ip = '.'.join(str(b) for b in peers[i:i+4])
        port = int.from_bytes(peers[i+4:i+6], 'big')
        peer_list.append((ip, port))
    return peer_list

# --- Step 3: Connect to peer and handshake ---
def handshake(sock, info_hash, peer_id):
    pstr = b'BitTorrent protocol'
    msg = struct.pack('>B', len(pstr)) + pstr + b'\x00'*8 + info_hash + peer_id
    sock.sendall(msg)
    resp = sock.recv(68)
    if resp[28:48] != info_hash:
        raise Exception('Info hash does not match')

# --- Step 4: Download pieces ---
def download(meta, peer, peer_id):
    sock = socket.socket()
    sock.settimeout(5)
    sock.connect(peer)
    handshake(sock, meta['info_hash'], peer_id)
    # Send interested
    sock.sendall(b'\x00\x00\x00\x01\x02')
    # Wait for unchoke
    while True:
        msg = sock.recv(4096)
        if b'\x01' in msg:  # unchoke
            break
    # Download first piece (for demo)
    piece_index = 0
    begin = 0
    length = min(meta['piece_length'], meta['length'])
    # Send request
    req = struct.pack('>IBIII', 13, 6, piece_index, begin, length)
    sock.sendall(req)
    # Receive piece
    data = b''
    while len(data) < length + 13:
        chunk = sock.recv(length + 13 - len(data))
        if not chunk:
            break
        data += chunk
    # Piece message: <len=0009+X><id=7><index><begin><block>
    if data[4] == 7:
        block = data[13:]
        with open(meta['name'] + '.part', 'wb') as f:
            f.write(block)
        print(f"Downloaded first piece to {meta['name']}.part")
    else:
        print("Failed to download piece.")
    sock.close()

# --- Main ---
def main():
    import sys
    if len(sys.argv) < 2:
        print("Usage: python client.py <file.torrent>")
        return
    meta = parse_torrent(sys.argv[1])
    peer_id = b'-PC0001-' + bytes(random.choices(b'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ', k=12))
    peers = get_peers(meta, peer_id)
    print(f"Found {len(peers)} peers. Connecting to first peer...")
    if peers:
        try:
            download(meta, peers[0], peer_id)
        except Exception as e:
            print(f"Error: {e}")
    else:
        print("No peers found.")

if __name__ == '__main__':
    main()
