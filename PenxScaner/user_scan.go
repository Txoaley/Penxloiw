package main

import (
	"encoding/json"
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

type PortInfo struct {
	Description string `json:"description"`
	Udp         bool   `json:"udp"`
	Status      string `json:"status"`
	Port        int    `json:"port,string"` // JSON'da "port" string olarak tutulmuş
	Tcp         bool   `json:"tcp"`
}

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
	fmt.Println("\n\n _______ ")
	fmt.Println("/       \\")
	fmt.Println("$$$$$$$  |")
	fmt.Println("$$ |__$$ |")
	fmt.Println("$$    $$/  /$$$$$$   |$$$$$$$  | $$  \\/$$/  /$$$$$$$/  /$$$$$$$/     $$$$$$    |$$$$$$$   |$$$$$$$  |  /$$$$$$  |  /$$$$$$  |")
	fmt.Println("$$$$$$$/   $$    $$  |$$ |  $$ |  $$  $$<   $$          $$ |         /    $$ |  |$$ |  $$  |$$ |  $$ |  $$    $$ |  $$ |  $$/ ")
	fmt.Println("$$ |       $$$$$$$$/  $$ |  $$ |  /$$$$  \\   $$$$$$   |$$\\        /$$$$$$$ |  |$$ |  $$  |$$ |  $$ |  $$$$$$$$/   $$ |      ")
	fmt.Println("$$ |       $$        |$$ |  $$ | /$$/ $$  |/      $$/   $$ ______   $$    $$     $$   |$$  |  $$ |$$ | |$$         |$$ |     ")
	fmt.Println("$$/         $$$$$$$/  $$/   $$/  $$/   $$/  $$$$$$$/    \\$$$$$$$/   $$$$$$$/    $$/   $$/  $$/   $$/   $$$$$$$/    $$/      ")

	fmt.Print("\n \n")

	var sd scanData
	fmt.Print("IP adresini girin: ")
	fmt.Scan(&sd.ip)

	fmt.Print("Lhost girin: ")
	fmt.Scan(&sd.lhost)
	sd.openPorts = make(chan int, 100)
	sd.stopChan = make(chan struct{})

	packets, err := createPackets(sd.lhost, sd.ip, sd.port)
	if err != nil {
		log.Fatalf("Paket oluşturma hatası: %v\n", err)
	}

	var secenek string
	var baslangıç, son int

	fmt.Print("\nTarama seçenekleri: \n \n [1] Tcp Ack Scan \n \n [2] Tcp Window Scan \n \n [3] Tcp Ack İcmp Scan \n \n [4] Os Scan \n  \n [5] Aktiflik Test \n \n Seçeneğiniz: \n  \n")
	fmt.Scan(&secenek)

	var port_seçenek string
	fmt.Print("\n Port seçenekleri: \n \n [1] 1-1024 (Default) \n\n [2] 1-13.107 \n\n [3] Tüm portlar(1-65.535) \n\n [4] Sizin seçeneğiniz \n\n")
	fmt.Scan(&port_seçenek)

	switch port_seçenek {

	case "1":
		baslangıç = 1
		son = 1024
	case "2":
		baslangıç = 1
		son = 13107
	case "3":
		baslangıç = 1
		son = 65535
	case "4":
		fmt.Print("Başlangıç portu:   ")
		fmt.Scan(&baslangıç)

		fmt.Print("Son taranıcak port:   ")
		fmt.Scan(&son)

	}

	var wg sync.WaitGroup

	fmt.Println("Port     --Protokol--     Bilgi       Durumu  ")
	switch secenek {
	case "1":
		wg.Add(1)
		go TcpAckScan(&wg, sd.ip, sd.lhost, packets.AckPacket, sd.openPorts, sd.stopChan, baslangıç, son)
	case "2":
		wg.Add(1)
		go windows_scan(sd.ip, baslangıç, son, sd.stopChan, &wg, packets.WindowPacket)
	case "3":
		wg.Add(1)
		go AckIcmpScan(&wg, sd.ip, baslangıç, son, packets.AckPacket, sd.openPorts, sd.stopChan)
	case "4":
		go os_data(sd.ip, baslangıç, son, &wg)
	case "5":
		go aktiflik(sd.ip)
	default:
		fmt.Println("Geçersiz seçenek")
		return
	}

	wg.Wait()
	fmt.Println("Tarama bitti")
}

func read(filename string) ([]PortInfo, error) {
	var ports []PortInfo

	file, err := os.Open(filename)
	if err != nil {
		return ports, err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	err = decoder.Decode(&ports)
	if err != nil {
		return ports, err
	}

	return ports, nil
}
func getPortInfo(port int) (PortInfo, error) {
	ports, err := read("ports.lists.json")
	if err != nil {
		return PortInfo{}, err
	}

	for _, p := range ports {
		if p.Port == port {
			return p, nil
		}
	}

	return PortInfo{}, fmt.Errorf("port bilgisi bulunamadı")
}

func port_bilgi(port int) {
	portInfo, err := getPortInfo(port)
	if err != nil {
	}
	fmt.Print(port, "    ")
	fmt.Print(portInfo.Tcp, "  ")
	fmt.Print(portInfo.Udp, "  ")
	fmt.Print(portInfo.Description, "    ")
	fmt.Print(portInfo.Status)
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

// ip, başlangıç , son, stopchan, wg, packet
func windows_scan(ip string, baslangıç int, son int, stopChan chan struct{}, wg *sync.WaitGroup, windowPacket []byte) {
	defer wg.Done()

	for port := baslangıç; port <= son; port++ {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()

			ln, err := net.Listen("tcp", fmt.Sprintf("%s:%d", ip, port))
			if err != nil {
				return
			}
			defer ln.Close()

			conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", ip, port))
			if err != nil {
				return
			}
			defer conn.Close()

			_, err = conn.Write(windowPacket)
			if err != nil {
				return
			}

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
				port_bilgi(port)
			}
		}(port)
	}
}

// wg, ip , lhost, ackpacket, openport, stopchan, başlangıç, son
func TcpAckScan(wg *sync.WaitGroup, ip string, lhost string, ackPacket []byte, openPorts chan int, stopChan chan struct{}, başlangıç int, son int) {
	defer wg.Done()

	for port := başlangıç; port <= son; port++ {
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
			port_bilgi(port)
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

func os_data(ip string, baslangıç int, son int, wg *sync.WaitGroup) {
	for port := baslangıç; port <= son; port++ {
		go func(port int) {
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
		}(port)
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

// wg, ip, baslangıç, son, ackpaket, openport, stopchan
func AckIcmpScan(wg *sync.WaitGroup, ip string, baslangıç, son int, ackPacket []byte, openPorts chan int, stopChan chan struct{}) {
	defer wg.Done()
	for port := baslangıç; port <= son; port++ {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			conn, err := net.Dial("ip4:icmp", ip)
			if err != nil {
				log.Printf("Bağlantı kurulamadı: %v", err)
				return
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
				log.Printf("ICMP paketi oluşturulamadı: %v", err)
				return
			}

			if _, err := conn.Write(messageBytes); err != nil {
				log.Printf("ICMP paketi gönderilemedi: %v", err)
				return
			}

			buffer := make([]byte, 1500)
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, err := conn.Read(buffer)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					return
				}
				log.Printf("ICMP paketi okunamadı: %v", err)
				return
			}

			packet, err := icmp.ParseMessage(1, buffer[:n])
			if err != nil {
				log.Printf("ICMP paketi çözümlenemedi: %v", err)
				return
			}

			switch packet.Type {
			case ipv4.ICMPTypeEchoReply:
				fmt.Printf("%d portu açık\n", port)
				openPorts <- port
			}
			port_bilgi(port)
		}(port)
	}
}
func yanıt(packetData []byte) {
	packet := gopacket.NewPacket(packetData, layers.LayerTypeTCP, gopacket.Default)
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		if tcp.SYN && tcp.ACK {
			fmt.Println("Port açık")
		}
	}
}
func aktiflik(ip string) {

	echoRequest := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte("help\r\n"),
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
