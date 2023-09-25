# Packet2Mongo

## Description
Capture packets off the wire and store them in a MongoDB database.

## Usage
```
usage: packet2mongo.py <interface> <mongo_uri> [capture_tags]
```

## Example
Pre-requisite: MongoDB server running on localhost (`bash scripts/start_mongo.sh`)
```bash
go build .
./packet2mongo en0 mongodb://localhost
```