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

type Packet struct {
	AckPacket    []byte
	WindowPacket []byte
	NullPacket   []byte
	XmasPacket   []byte
	UdpPacket    []byte
}

func main() {
	var sd scanData
	fmt.Print("IP adresini girin: ")
	fmt.Scan(&sd.ip)

	fmt.Print("Lhost girin: ")
	fmt.Scan(&sd.lhost)
	sd.openPorts = make(chan int, 100)
	sd.stopChan = make(chan struct{})

	go aktiflik(sd.ip)

	packets, err := createPackets(sd.lhost, sd.ip, sd.port)
	if err != nil {
		log.Fatalf("Paket oluşturulamadı: %v", err)
	}

	var wg sync.WaitGroup

	wg.Add(1)
	go TcpAckScan(&wg, sd.ip, sd.lhost, packets.AckPacket, sd.openPorts, sd.stopChan)

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
		Ack_İcmp_Scan(sd.ip, port, packets.AckPacket, sd.openPorts, sd.stopChan)
	}

	for port := 1; port <= 65535; port++ {
		wg.Add(1)
		go os_data(sd.ip, port, &wg)
	}

	for port := 1; port <= 65535; port++ {
		wg.Add(1)
		go windows_scan(sd.ip, port, sd.stopChan, &wg, packets.WindowPacket)
	}

	wg.Wait()
}

func createPackets(localIP, targetIP string, port int) (Packet, error) {
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
	ackPacket.SetNetworkLayerForChecksum(ipLayer)

	windowPacket := &layers.TCP{
		SrcPort: layers.TCPPort(port),
		DstPort: layers.TCPPort(port),
		Seq:     0,
		Window:  30600,
	}
	windowPacket.SetNetworkLayerForChecksum(ipLayer)

	nullPacket := &layers.TCP{
		SrcPort: layers.TCPPort(port),
		DstPort: layers.TCPPort(port),
		Seq:     0,
	}
	nullPacket.SetNetworkLayerForChecksum(ipLayer)

	xmasPacket := &layers.TCP{
		SrcPort: layers.TCPPort(port),
		DstPort: layers.TCPPort(port),
		Seq:     0,
		Window:  30600,
		ACK:     true,
		PSH:     true,
		RST:     true,
	}
	xmasPacket.SetNetworkLayerForChecksum(ipLayer)

	ip_udp := &layers.IPv4{
		SrcIP:    net.ParseIP(localIP).To4(),
		DstIP:    net.ParseIP(targetIP).To4(),
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
	}

	udp := &layers.UDP{
		SrcPort: layers.UDPPort(12345),
		DstPort: layers.UDPPort(53),
	}
	udp.SetNetworkLayerForChecksum(ip_udp)
	payload := gopacket.Payload([]byte("help\r\n"))

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err := gopacket.SerializeLayers(buffer, opts, ip_udp, udp, payload)
	if err != nil {
		return Packet{}, err
	}

	bufferAck := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(bufferAck, opts, ipLayer, ackPacket); err != nil {
		return Packet{}, err
	}

	bufferWindow := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(bufferWindow, opts, ipLayer, windowPacket); err != nil {
		return Packet{}, err
	}

	bufferNull := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(bufferNull, opts, ipLayer, nullPacket); err != nil {
		return Packet{}, err
	}

	bufferXmas := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(bufferXmas, opts, ipLayer, xmasPacket); err != nil {
		return Packet{}, err
	}

	return Packet{
		AckPacket:    bufferAck.Bytes(),
		WindowPacket: bufferWindow.Bytes(),
		NullPacket:   bufferNull.Bytes(),
		XmasPacket:   bufferXmas.Bytes(),
		UdpPacket:    buffer.Bytes(),
	}, nil
}

func windows_scan(ip string, port int, stopchan chan struct{}, wg *sync.WaitGroup, windowPacket []byte) {
	defer wg.Done()

	ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	_, err = conn.Write(windowPacket)
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		<-stopchan
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

func TcpAckScan(wg *sync.WaitGroup, ip string, lhost string, ackPacket []byte, openPorts chan int, stopChan chan struct{}) {
	defer wg.Done()

	for port := 1; port <= 65535; port++ {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()

			go listen(lhost, port, stopChan, wg)

			conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", ip, port))
			if err != nil {
				return
			}
			defer conn.Close()

			_, err = conn.Write(ackPacket)
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

//	Version       = <must be specified>
//	Len           = <must be specified>
//	TOS           = <must be specified>
//	TotalLen      = <must be specified>
//	ID            = platform sets an appropriate value if ID is zero
//	FragOff       = <must be specified>
//	TTL           = <must be specified>
//	Protocol      = <must be specified>
//	Checksum      = platform sets an appropriate value if Checksum is zero
//	Src           = platform sets an appropriate value if Src is nil
//	Dst           = <must be specified>
//	Options       = optional

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

func os_data(ip string, port int, wg *sync.WaitGroup) {
	defer wg.Done()

	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		fmt.Printf("Bağlantı kurulamadı: %v\n", err)
		return
	}
	
	defer conn.Close()

	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		fmt.Printf("Yanıt alınamadı: %v\n", err)
		return
	}

	fmt.Printf("Kaynaktan alınan yanıt: %s\n", buffer[:n])

	message := "help\r\n"
	_, err = conn.Write([]byte(message))
	if err != nil {
		fmt.Printf("Veri gönderimi başarısız oldu: %v\n", err)
		return
	}

	conn.Read(buffer)
	fmt.Print(buffer)

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

func Ack_İcmp_Scan(ip string, port int, ackPacket []byte, openPorts chan int, stopChan chan struct{}) {
	conn, err := net.Dial("ip4:icmp", ip)
	if err != nil {
		log.Fatalf("Bağlantı kurulamadı: %v", err)
	}
	defer conn.Close()

	message := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: ackPacket,
		},
	}

	messageBytes, err := message.Marshal(nil)
	if err != nil {
		log.Fatalf("ICMP paketi oluşturulamadı: %v", err)
	}

	if _, err := conn.Write(messageBytes); err != nil {
		log.Fatalf("ICMP paketi gönderilemedi: %v", err)
	}

	buffer := make([]byte, 1500)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buffer)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return
		}
		log.Fatalf("ICMP paketi okunamadı: %v", err)
	}

	packet, err := icmp.ParseMessage(1, buffer[:n])
	if err != nil {
		log.Fatalf("ICMP paketi çözümlenemedi: %v", err)
	}

	switch packet.Type {
	case ipv4.ICMPTypeEchoReply:
		fmt.Printf("%d portu açık\n", port)
		openPorts <- port
	default:
	}
}

func aktiflik(ip string) {

	echoRequest := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte(" HELP\r\n"),
		},
	}

	c, err := net.Dial("ip4:icmp", ip)
	if err != nil {
		fmt.Println("Hedefe bağlanılamadı:", err)
		return
	}
	defer c.Close()

	echoRequestBytes, err := echoRequest.Marshal(nil)
	if err != nil {
		return
	}

	_, err = c.Write(echoRequestBytes)
	if err != nil {
		return
	}

	reply := make([]byte, 1500)
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := c.Read(reply)
	if err != nil {
		return
	}

	echoReply, err := icmp.ParseMessage(1, reply[:n])
	if err != nil {
		return
	}

	switch echoReply.Type {
	case ipv4.ICMPTypeEchoReply:
		fmt.Println("Hedef aktif!")
	default:
		fmt.Println("Hedef yanıt vermedi.")
	}
}
