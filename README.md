# BitTorrent Client (Python)

This project is a simplified BitTorrent client implemented in Python for educational and resume purposes. It demonstrates the core concepts of the BitTorrent protocol, including parsing .torrent files, communicating with trackers, connecting to peers, and downloading file pieces in a peer-to-peer fashion.

## Features
- Parse .torrent files (bencode format)
- Connect to trackers to discover peers
- Download file pieces from multiple peers
- Upload pieces to other peers (seeding)
- Assemble the final file from pieces

## Usage
1. Place a .torrent file in the project directory.
2. Run the client: `python src/main.py <torrent-file>`
3. The client will download the file and show logs for each step.

## Note
This is a simplified implementation for learning and demonstration. For real-world use, consider using established BitTorrent clients. 