package main

import (
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	// Interface to capture on
	iface = "en0"

	// Mongodb connection info
	mongoURI = "mongodb://localhost:27017"
	dbName   = "traffic"
	colName  = "packets"

	// The same default as tcpdump.
	defaultSnapLen = 262144
)

// Packet struct
type Packet struct {
	Src    string
	Dst    string
	TTL    uint8
	Length uint16
}

func main() {

	// Open pcap handle
	handle, err := pcap.OpenLive("en0", defaultSnapLen, true,
		pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	// Connect to mongodb
	client, err := mongo.Connect(nil, options.Client().ApplyURI(mongoURI))
	if err != nil {
		log.Fatal(err)
	}
	defer client.Disconnect(nil)
	database := client.Database(dbName)
	collection := database.Collection(colName)

	// Capture packets
	packets := gopacket.NewPacketSource(
		handle, handle.LinkType()).Packets()
	for pkt := range packets {
		// Add the packet to the database
		netLayer := pkt.NetworkLayer()
		if netLayer == nil {
			continue
		}
		dst := netLayer.NetworkFlow().Dst().String()
		src := netLayer.NetworkFlow().Src().String()
		// Get packet ttl
		ipLayer := pkt.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			continue
		}
		ttl := ipLayer.(*layers.IPv4).TTL
		// Get packet length
		length := ipLayer.(*layers.IPv4).Length
		// Insert packet into database
		packet := Packet{
			Src:    src,
			Dst:    dst,
			TTL:    ttl,
			Length: length,
		}
		_, err := collection.InsertOne(nil, packet)
		if err != nil {
			log.Fatal(err)
		}
	}
}
