# Packet2Mongo

## Description
Capture packets off the wire and store them in a MongoDB database.

## Usage
```
$ ./packet2mongo --help
  -c string
        Mongodb collection name (default "packets")
  -d string
        Mongodb database name (default "traffic")
  -f string
        Pcap file to read from instead of live capture
  -i string
        Interface to get packets from (default "eth0")
  -m string
        Mongodb URI (default "mongodb://localhost:27017")
  -s int
        SnapLen for pcap packet capture (default 16384)
  -t string
        Comma separated list of tags to add to each packet
```

## Pre-requisites
* libpcap-dev installed
  * Linux: `sudo apt-get install libpcap-dev`
  * Mac: `brew install libpcap`
  * Windows: Install linux
* MongoDB server running on localhost (`bash scripts/start_mongo.sh`)