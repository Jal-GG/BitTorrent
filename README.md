# BitTorrent Client 

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
