import bencodepy
import requests
import socket
import random
import hashlib
import struct
import os
from urllib.parse import urlparse, urlencode
import threading
import queue

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
    # Prepare parameters except info_hash and peer_id
    params = {
        'port': str(port),
        'uploaded': '0',
        'downloaded': '0',
        'left': str(meta['length']),
        'compact': '1',
        'event': 'started'
    }
    # Build base URL
    url = meta['announce'] + '?'
    # Add info_hash and peer_id as percent-encoded bytes
    url += 'info_hash=' + requests.utils.quote(meta['info_hash'], safe='')
    url += '&peer_id=' + requests.utils.quote(peer_id, safe='')
    # Add the rest of the params
    for k, v in params.items():
        url += f'&{k}={v}'
    r = requests.get(url, timeout=10)
    tracker = bencodepy.decode(r.content)
    if b'failure reason' in tracker:
        print('Tracker failure:', tracker[b'failure reason'].decode(errors='replace'))
        return []
    if b'peers' not in tracker:
        print('No peers found in tracker response:', tracker)
        return []
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
def download_worker(meta, peer, peer_id, piece_queue, piece_hashes, file_lock, file_name, piece_length, file_length):
    try:
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
        while True:
            try:
                piece_index = piece_queue.get_nowait()
            except queue.Empty:
                break
            begin = 0
            length = min(piece_length, file_length - piece_index * piece_length)
            req = struct.pack('>IBIII', 13, 6, piece_index, begin, length)
            sock.sendall(req)
            data = b''
            while len(data) < length + 13:
                chunk = sock.recv(length + 13 - len(data))
                if not chunk:
                    break
                data += chunk
            if len(data) < length + 13 or data[4] != 7:
                print(f"Peer {peer} failed to download piece {piece_index}")
                piece_queue.put(piece_index)  # Put back for another peer
                continue
            block = data[13:]
            if hashlib.sha1(block).digest() != piece_hashes[piece_index]:
                print(f"Peer {peer} hash mismatch for piece {piece_index}")
                piece_queue.put(piece_index)
                continue
            with file_lock:
                with open(file_name + '.part', 'r+b') as f:
                    f.seek(piece_index * piece_length)
                    f.write(block)
            print(f"Peer {peer} downloaded piece {piece_index}")
        sock.close()
    except Exception as e:
        print(f"Peer {peer} error: {e}")

def download(meta, peers, peer_id):
    num_pieces = len(meta['pieces']) // 20
    piece_hashes = [meta['pieces'][i*20:(i+1)*20] for i in range(num_pieces)]
    file_length = meta['length']
    piece_length = meta['piece_length']
    file_name = meta['name']
    with open(file_name + '.part', 'wb') as f:
        f.truncate(file_length)
    piece_queue = queue.Queue()
    for i in range(num_pieces):
        piece_queue.put(i)
    file_lock = threading.Lock()
    threads = []
    max_peers = min(4, len(peers))
    print(f"Starting download with {max_peers} peers and {num_pieces} pieces")
    for i in range(max_peers):
        t = threading.Thread(target=download_worker, args=(meta, peers[i], peer_id, piece_queue, piece_hashes, file_lock, file_name, piece_length, file_length))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    print(f"Download complete. Saved as {file_name}.part")

# --- Main ---
def main():
    import sys
    if len(sys.argv) < 2:
        print("Usage: python client.py <file.torrent>")
        return
    meta = parse_torrent(sys.argv[1])
    peer_id = b'-PC0001-' + bytes(random.choices(b'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ', k=12))
    peers = get_peers(meta, peer_id)
    print(f"Found {len(peers)} peers. Connecting to up to 4 peers...")
    if peers:
        try:
            download(meta, peers, peer_id)
        except Exception as e:
            print(f"Error: {e}")
    else:
        print("No peers found.")

if __name__ == '__main__':
    main()
