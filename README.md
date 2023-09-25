# Packet2Mongo

## Description
Capture packets off the wire and store them in a MongoDB database.

## Usage
```
usage: packet2mongo.py <interface> <mongo_uri> [capture_tags]
```

## Example
Pre-requisite:
* libpcap-dev installed
  * Linux: `sudo apt-get install libpcap-dev`
  * Mac: `brew install libpcap`
  * Windows: Install linux
* MongoDB server running on localhost (`bash scripts/start_mongo.sh`)

Run:

```bash
go build .
./packet2mongo eth0 mongodb://localhost
```