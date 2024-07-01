package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type scanData struct {
	ip        string
	lhost     string
	port      int
	openPorts chan int
	stopChan  chan struct{}
}

type packet struct {
	ipLayer      *layers.IPv4
	ackPacket    []byte
	windowPacket []byte
	nullPacket   []byte
	xmasPacket   []byte
}

func main() {
	var sd scanData
	fmt.Print("IP adresini girin: ")
	fmt.Scan(&sd.ip)

	fmt.Print("Lhost girin: ")
	fmt.Scan(&sd.lhost)
	sd.openPorts = make(chan int, 100)
	sd.stopChan = make(chan struct{})

	go aktiflik(sd.ip) // Hedefin aktif olup olmadığını kontrol eder

	packets, err := createPackets(sd.lhost, sd.ip, sd.port)
	if err != nil {
		log.Fatalf("Paket oluşturulamadı: %v", err)
	}

	var wg sync.WaitGroup

	wg.Add(1)
	go TcpAckScan(&wg, sd.ip, sd.lhost, packets.ackPacket, sd.openPorts, sd.stopChan)

	go func() {
		wg.Wait()
		close(sd.stopChan)
		fmt.Println("Tarama bitti")
	}()

	go func() {
		for port := range sd.openPorts {
			wg.Add(1)
			go listen(sd.lhost, port, sd.stopChan, &wg)
		}
	}()
	for port := 1; port <= 65535; port++ {
		wg.Add(1)
		Ack_İcmp_Scan(sd.ip, port, packets.ackPacket, sd.openPorts, sd.stopChan)
	}

	wg.Wait()
}

func createPackets(localIP, targetIP string, port int) (packet, error) {
	ipLayer := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TOS:      0,
		Id:       54321,
		Flags:    layers.IPv4DontFragment,
		TTL:      255,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.ParseIP(localIP).To4(),
		DstIP:    net.ParseIP(targetIP).To4(),
	}
	ackPacket := &layers.TCP{
		SrcPort: layers.TCPPort(port),
		DstPort: layers.TCPPort(port),
		Seq:     0,
		Window:  30600,
		ACK:     true,
	}
	windowPacket := &layers.TCP{
		SrcPort: layers.TCPPort(port),
		DstPort: layers.TCPPort(port),
		Seq:     0,
		Window:  30600,
	}
	nullPacket := &layers.TCP{
		SrcPort: layers.TCPPort(port),
		DstPort: layers.TCPPort(port),
		Seq:     0,
	}
	xmasPacket := &layers.TCP{
		SrcPort: layers.TCPPort(port),
		DstPort: layers.TCPPort(port),
		Seq:     0,
		Window:  30600,
		ACK:     true,
		PSH:     true,
		RST:     true,
	}

	bufferAck := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	if err := gopacket.SerializeLayers(bufferAck, opts, ipLayer, ackPacket); err != nil {
		return packet{}, err
	}

	bufferWindow := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(bufferWindow, opts, ipLayer, windowPacket); err != nil {
		return packet{}, err
	}

	bufferNull := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(bufferNull, opts, ipLayer, nullPacket); err != nil {
		return packet{}, err
	}

	bufferXmas := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(bufferXmas, opts, ipLayer, xmasPacket); err != nil {
		return packet{}, err
	}

	return packet{
		ipLayer:      ipLayer,
		ackPacket:    bufferAck.Bytes(),
		windowPacket: bufferWindow.Bytes(),
		nullPacket:   bufferNull.Bytes(),
		xmasPacket:   bufferXmas.Bytes(),
	}, nil
}

func TcpAckScan(wg *sync.WaitGroup, ip string, lhost string, ackPacket []byte, openPorts chan int, stopChan chan struct{}) {
	defer wg.Done()

	for port := 1; port <= 65535; port++ {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()

			// Dinlemeye başla
			go listen(lhost, port, stopChan, wg)

			// Paketi gönder
			conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", ip, port))
			if err != nil {
				return
			}
			defer conn.Close()

			_, err = conn.Write(ackPacket) // Örnek veri gönderimi
			if err != nil {
				return
			}

			buffer := make([]byte, 2048)
			_, err = conn.Read(buffer)
			if err != nil {
				return
			}

			fmt.Printf("%d portu açık\n", port)
			openPorts <- port
		}(port)
	}
}

func listen(ip string, port int, stopChan chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	go func() {
		<-stopChan
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	buffer := make([]byte, 2048)
	_, err := conn.Read(buffer)
	if err != nil {
		log.Println("Port kapalı, veri göndermedi", err)
		return
	}
	fmt.Printf("Gelen veri: %s\n", string(buffer))
}
func Ack_İcmp_Scan(ip string, port int, ack_payload []byte, openPorts chan int, stopChan chan struct{}) {
	echoRequest := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: ack_payload,
		},
	}

	echoRequestBytes, err := echoRequest.Marshal(nil)
	if err != nil {
	}

	c, err := net.Dial("ip4:icmp", ip)
	if err != nil {
	}
	defer c.Close()

	_, err = c.Write(echoRequestBytes)
	if err != nil {
	}

	reply := make([]byte, 1500)
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := c.Read(reply)
	if err != nil {
	}

	echoReply, err := icmp.ParseMessage(1, reply[:n])
	if err != nil {
		return
	}

	switch echoReply.Type {
	case ipv4.ICMPTypeEchoReply:
		fmt.Printf("%s:%d portu açık\n", ip, port)
		openPorts <- port
	default:
		fmt.Printf("%s:%d portu kapalı\n", ip, port)
	}
}

func aktiflik(ip string) {
	// ICMP Echo isteği oluştur
	echoRequest := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte("Hello"),
		},
	}

	// ICMP bağlantısı aç
	c, err := net.Dial("ip4:icmp", ip)
	if err != nil {
		fmt.Println("Hedefe bağlanılamadı:", err)
		return
	}
	defer c.Close()

	// Echo isteğini serialize et
	echoRequestBytes, err := echoRequest.Marshal(nil)
	if err != nil {
		fmt.Println("ICMP paketi oluşturma hatası:", err)
		return
	}

	// ICMP Echo isteğini gönder
	_, err = c.Write(echoRequestBytes)
	if err != nil {
		fmt.Println("ICMP paketi gönderme hatası:", err)
		return
	}

	// ICMP Echo yanıtını al
	reply := make([]byte, 1500)
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := c.Read(reply)
	if err != nil {
		fmt.Println("Hedef aktif değil veya yanıt vermedi.")
		return
	}

	// ICMP Echo yanıtını parse et
	echoReply, err := icmp.ParseMessage(1, reply[:n])
	if err != nil {
		fmt.Println("ICMP yanıtını ayrıştırma hatası:", err)
		return
	}

	// Yanıt türüne göre durumu belirle
	switch echoReply.Type {
	case ipv4.ICMPTypeEchoReply:
		fmt.Println("Hedef aktif!")
	default:
		fmt.Println("Hedef yanıt vermedi.")
	}
}
