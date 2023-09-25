package main

import (
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	// Interface to capture on
	// iface = "lo0"

	// Mongodb connection info
	// mongoURI = "mongodb://localhost:27017"
	dbName  = "traffic"
	colName = "packets"

	// The same default as tcpdump.
	defaultSnapLen = 262144
)

type TCPFlag struct {
	NS  bool
	CWR bool
	ECE bool
	URG bool
	ACK bool
	PSH bool
	RST bool
	SYN bool
	FIN bool
}

// Packet struct
type Packet struct {
	Iface       string
	Timestamp   int64
	SrcMac      string
	DstMac      string
	IpVer       uint8
	SrcIp       string
	DstIp       string
	TTL         uint8
	Protocol    string
	SrcPort     uint64
	DstPort     uint64
	TCPSeq      uint32
	TCPAck      uint32
	TCPFlag     TCPFlag
	TCPWindow   uint16
	TCPUrgent   uint16
	TCPOptions  []layers.TCPOption
	PayloadLen  uint16
	Payload     []byte
	CaptureTags []string
}

func main() {

	// Read in cmd line args
	if len(os.Args) != 3 {
		log.Fatal("Usage: packet2mongo <interface> <mongodb_uri> [capture_tags]")
	}
	iface := os.Args[1]
	mongoURI := os.Args[2]

	// Get capture tags
	var captureTags []string
	if len(os.Args) > 3 {
		captureTags = os.Args[3:]
	}

	// Get mongo port number from URI
	mongoPort, err := strconv.ParseUint(mongoURI[len(mongoURI)-5:], 10, 16)
	if err != nil {
		mongoPort = 27017
	}

	// Open pcap handle
	handle, err := pcap.OpenLive(iface, defaultSnapLen, true,
		pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	// Ignore traffic on the mongodb port
	err = handle.SetBPFFilter(fmt.Sprintf("not port %d", mongoPort))
	if err != nil {
		log.Fatal(err)
	}

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

		packet := Packet{
			Iface:       iface,
			CaptureTags: captureTags,
		}

		// Get link layer
		linkLayer := pkt.LinkLayer()
		if linkLayer == nil {
			continue
		}
		// Get network layer
		netLayer := pkt.NetworkLayer()
		if netLayer == nil {
			continue
		}

		// Get IP Layer
		ipLayer := pkt.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			packet.IpVer = 4
			packet.TTL = ipLayer.(*layers.IPv4).TTL
			packet.Protocol = ipLayer.(*layers.IPv4).Protocol.String()
		} else {
			// Try IPv6
			ipLayer = pkt.Layer(layers.LayerTypeIPv6)
			if ipLayer != nil {
				continue
			}
			packet.IpVer = 6
			packet.TTL = ipLayer.(*layers.IPv6).HopLimit
			packet.Protocol = ipLayer.(*layers.IPv6).NextHeader.String()
		}
		// Get transport layer
		transportLayer := pkt.TransportLayer()
		if transportLayer == nil {
			continue
		}

		packet.Timestamp = pkt.Metadata().Timestamp.UnixNano()
		packet.SrcMac = linkLayer.LinkFlow().Src().String()
		packet.DstMac = linkLayer.LinkFlow().Dst().String()
		packet.DstIp = netLayer.NetworkFlow().Dst().String()
		packet.SrcIp = netLayer.NetworkFlow().Src().String()
		packet.SrcPort, err = strconv.ParseUint(transportLayer.TransportFlow().Src().String(), 10, 16)
		if err != nil {
			log.Fatal(err)
		}
		dstPort, err := strconv.ParseUint(transportLayer.TransportFlow().Dst().String(), 10, 16)
		if err != nil {
			log.Fatal(err)
		}
		if transportLayer.LayerType() == layers.LayerTypeTCP {
			tcpLayer := transportLayer.(*layers.TCP)
			packet.TCPSeq = tcpLayer.Seq
			packet.TCPAck = tcpLayer.Ack
			packet.TCPFlag.NS = tcpLayer.NS
			packet.TCPFlag.CWR = tcpLayer.CWR
			packet.TCPFlag.ECE = tcpLayer.ECE
			packet.TCPFlag.URG = tcpLayer.URG
			packet.TCPFlag.ACK = tcpLayer.ACK
			packet.TCPFlag.PSH = tcpLayer.PSH
			packet.TCPFlag.RST = tcpLayer.RST
			packet.TCPFlag.SYN = tcpLayer.SYN
			packet.TCPFlag.FIN = tcpLayer.FIN

			packet.TCPWindow = tcpLayer.Window
			packet.TCPUrgent = tcpLayer.Urgent
			packet.TCPOptions = tcpLayer.Options

			packet.PayloadLen = uint16(len(tcpLayer.Payload))
			packet.Payload = tcpLayer.Payload
		} else if transportLayer.LayerType() == layers.LayerTypeUDP {
			udpLayer := transportLayer.(*layers.UDP)
			packet.DstPort = uint64(dstPort)
			packet.PayloadLen = uint16(len(udpLayer.Payload))
			packet.Payload = udpLayer.Payload
		} else {
			continue
		}

		_, err = collection.InsertOne(nil, packet)
		if err != nil {
			log.Fatal(err)
		}
	}
}
