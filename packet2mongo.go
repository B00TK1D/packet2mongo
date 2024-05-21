package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var iface = flag.String("i", "eth0", "Interface to get packets from")
var pcapFile = flag.String("f", "", "Pcap file to read from instead of live capture")
var mongoURI = flag.String("m", "mongodb://localhost:27017", "Mongodb URI")
var dbName = flag.String("d", "traffic", "Mongodb database name")
var colName = flag.String("c", "packets", "Mongodb collection name")
var snaplen = flag.Int("s", 16<<10, "SnapLen for pcap packet capture")
var captureTags = flag.String("t", "", "Comma separated list of tags to add to each packet")

var ctxTodo = context.TODO()

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
	Processed   bool
}

func main() {

	// Read in cmd line args
	flag.Parse()

	// Get mongo port number from URI
	mongoPort, err := strconv.ParseUint((*mongoURI)[len(*mongoURI)-5:], 10, 16)
	if err != nil {
		mongoPort = 27017
	}

	handle := new(pcap.Handle)
	// Open pcap handle
	if *pcapFile != "" {
		handle, err = pcap.OpenOffline(*pcapFile)
		if err != nil {
			panic(err)
		}
	} else {
		handle, err = pcap.OpenLive(*iface, int32(*snaplen), true, pcap.BlockForever)
		if err != nil {
			panic(err)
		}
	}
	defer handle.Close()

	// Ignore traffic on the mongodb port
	err = handle.SetBPFFilter(fmt.Sprintf("not port %d", mongoPort))
	if err != nil {
		log.Fatal(err)
	}

	// Connect to mongodb
	client, err := mongo.Connect(ctxTodo, options.Client().ApplyURI(*mongoURI))
	if err != nil {
		log.Fatal(err)
	}
	defer client.Disconnect(ctxTodo)
	database := client.Database(*dbName)
	collection := database.Collection(*colName)

	// Capture packets
	packets := gopacket.NewPacketSource(
		handle, handle.LinkType()).Packets()
	for pkt := range packets {

		log.Println(pkt)

		packet := Packet{
			Iface:       *iface,
			CaptureTags: strings.Split(*captureTags, ","),
			Processed:   false,
		}

		// Get link layer
		linkLayer := pkt.LinkLayer()
		if linkLayer != nil {
			packet.SrcMac = linkLayer.LinkFlow().Src().String()
			packet.DstMac = linkLayer.LinkFlow().Dst().String()
		}

		// Get network layer
		netLayer := pkt.NetworkLayer()
		if netLayer == nil {
			log.Println("No network layer")
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
				log.Println("No IP layer")
				continue
			}
			packet.IpVer = 6
			packet.TTL = ipLayer.(*layers.IPv6).HopLimit
			packet.Protocol = ipLayer.(*layers.IPv6).NextHeader.String()
		}
		// Get transport layer
		transportLayer := pkt.TransportLayer()
		if transportLayer == nil {
			log.Println("No transport layer")
			continue
		}

		packet.Timestamp = pkt.Metadata().Timestamp.UnixNano()
		packet.DstIp = netLayer.NetworkFlow().Dst().String()
		packet.SrcIp = netLayer.NetworkFlow().Src().String()
		packet.SrcPort, err = strconv.ParseUint(transportLayer.TransportFlow().Src().String(), 10, 16)
		if err != nil {
			log.Fatal(err)
		}
		packet.DstPort, err = strconv.ParseUint(transportLayer.TransportFlow().Dst().String(), 10, 16)
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
			packet.PayloadLen = uint16(len(udpLayer.Payload))
			packet.Payload = udpLayer.Payload
		} else {
			continue
		}

		_, err = collection.InsertOne(ctxTodo, packet)
		if err != nil {
			log.Fatal(err)
		}
	}
}
