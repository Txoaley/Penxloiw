package main

import (
	"fmt"
	"net"
	"sync"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type PortResult struct {
	port   int
	status string
}


func sendFin(target string, port int) {
	handle, err := pcap.OpenLive("eth0", 65535, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	ipLayer := &layers.IPv4{
		SrcIP:    net.ParseIP("your_source_ip"),
		DstIP:    net.ParseIP(target),
		Protocol: layers.IPProtocolTCP,
	}
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(12345),
		DstPort: layers.TCPPort(port),
		Seq:     1105024978,
		Window:  14600,
		ACK:     false,
		SYN:     false,
		FIN:     true,
		PSH:     false,
		URG:     false,
		RST:     false,
	}

	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	gopacket.SerializeLayers(buffer, opts, ipLayer, tcpLayer)

	if err := handle.WritePacketData(buffer.Bytes()); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Sent FIN packet to %s:%d\n", target, port)
}

func sendXmas(target string, port int) {
	handle, err := pcap.OpenLive("eth0", 65535, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	ipLayer := &layers.IPv4{
		SrcIP:    net.ParseIP("your_source_ip"),
		DstIP:    net.ParseIP(target),
		Protocol: layers.IPProtocolTCP,
	}
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(12345),
		DstPort: layers.TCPPort(port),
		Seq:     1105024978,
		Window:  14600,
		ACK:     false,
		SYN:     false,
		FIN:     true,
		PSH:     true,
		URG:     true,
		RST:     false,
	}

	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	gopacket.SerializeLayers(buffer, opts, ipLayer, tcpLayer)

	if err := handle.WritePacketData(buffer.Bytes()); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Sent Xmas packet to %s:%d\n", target, port)
}

func sendWindow(target string, port int) {
	handle, err := pcap.OpenLive("eth0", 65535, true, pcap.BlockForever) // ağ analiz için eth0, 65535 max byte ve port,  True ise daha detaylı bilgi alma ve trafiği ilzeme modu, pcap.blockforever sürekli paket dinleme modunu aktif eder.
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	ipLayer := &layers.IPv4{
		SrcIP:    net.ParseIP("your_source_ip"),
		DstIP:    net.ParseIP(target),
		Protocol: layers.IPProtocolTCP,
	}
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(port),
		DstPort: layers.TCPPort(port),
		Seq:     1105024978,
		Window:  14600,
		ACK:     false,
		SYN:     false,
		FIN:     false,
		PSH:     false,
		URG:     false,
		RST:     false,
	}

	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	gopacket.SerializeLayers(buffer, opts, ipLayer, tcpLayer)

	if err := handle.WritePacketData(buffer.Bytes()); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Sent Window packet to %s:%d\n", target, port)
}

func portTarama(protocol string, ip string, port int, results chan<- PortResult) {
	address := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.Dial(protocol, address)
	if err != nil {
		results <- PortResult{port: port, status: "Kapalı"}
		return
	}
	conn.Close()
	results <- PortResult{port: port, status: "Açık"}
}

func Aktiflik(string ip) {
	targetIP := net.IP{ip}

	echoRequest := icmp.Message{
		Type: ipv4.ICMPTypeEcho, // ICMP tipi: Echo Request, cevap pingi beklemeli
		Code: 0,                 // Kod: 0
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff, // Rastgele bir ID kullanabilirsiniz 16 bitlik ve pc özel numarası
			Seq:  1,                    // ICMP sırası
			Data: []byte("Hello ICMP"), // ICMP verisi
		},
	}

	// ICMP mesajını bytes'a çevirme
	b, err := m.Marshal(nil)
	if err != nil {
		log.Fatal(err)
	}

	// ICMP mesajını hedefe gönderme
	start := time.Now()
	_, err = c.WriteTo(b, &net.IPAddr{IP: destIP})
	if err != nil {
		log.Fatal(err)
	}

	// Yanıt bekleniyor
	reply := make([]byte, 1500)
	err = c.SetReadDeadline(time.Now().Add(3 * time.Second)) // Yanıtın 3 saniye içinde alınması bekleniyor
	if err != nil {
		log.Fatal(err)
	}
	_, _, err = c.ReadFrom(reply)
	if err != nil {
		log.Fatal("No reply")
	}

	// ICMP yanıtını pars etme
	rm, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), reply)
	if err != nil {
		log.Fatal(err)
	}
	duration := time.Since(start)

	// ICMP yanıtı çıktıları
	fmt.Printf("ICMP Reply from %s: seq=%d time=%v\n", destIP.String(), rm.Body.(*icmp.Echo).Seq, duration)
	
	echoRequestBytes, err := echoRequest.Marshal(nil)
	if err != nil {
		fmt.Println("ICMP paketi oluşturma hatası:", err)

	_, err = conn.Write(echoRequestBytes)
	if err != nil {
			fmt.Println("ICMP paketi gönderme hatası:", err)
			return
	}
	
	reply := make([]byte, 1500)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(reply)
	if err != nil {
			fmt.Println("Hedef aktif değil veya yanıt vermedi.")
			return
	}
	
	echoReply, err := icmp.ParseMessage(1, reply[:n])
	if err != nil {
			fmt.Println("ICMP yanıtını ayrıştırma hatası:", err)
			return
	}
	
	switch echoReply.Type {
		case ipv4.ICMPTypeEchoReply:
			fmt.Println("Hedef aktif!")
		default:
			fmt.Println("Hedef yanıt vermedi.")
	}
	
}

func main () {
	var (
		ip          string,
		port1, port2 int,
		protocol    string,
		kapalıChoice int,
	)
	fmt.Print("İp adresini girin: ")
	fmt.Scan(&ip)

	fmt.Print("Başlangıç portunu giriniz: ")
	fmt.Scan(&port1)

	fmt.Print("Bitiş portunu giriniz: ")
	fmt.Scan(&port2)

	fmt.Print("Protokolü seçiniz: \n [1] Tcp \n [2] Udp \n \n Sayı girin: ")
	var protocolChoice int
	fmt.Scan(&protocolChoice)

	fmt.Print("Kapalı portları görmek istiyor musunuz? \n [1] Evet \n [2] Hayır \n Lütfen sayı girin: ")
	fmt.Scan(&kapalıChoice)

	fmt.Print("Tarama yöntemleri: \n | [1]Tcp | \n | [2]Fın |\n | [3]Null | C \n | [4]Windows | \n | [5]Xmas |")
	fmt.scan(&Yöntem)

	if protocolChoice == 1 {
		protocol = "tcp"
	} else {
		protocol = "udp"
	}

	results := make(chan PortResult)

	switch Yöntem {
	case 1:
		for port := port1; port <= port2; port++ {
			go portTarama(protocol, ip, port, results)
		}
	case 2:
		for port := port1; port <= port2; port++ {
			go sendFin(ip, port)
		}
	case 4:
		for port := port1; port <= port2; port++ {
			go sendWindow(ip, port)
		}
	case 5:
		for port := port1; port <= port2; port++ {
			go sendXmas(ip, port)
		}
	default:
		fmt.Println("Geçersiz tarama yöntemi seçildi.")
	}

	openPorts := []int{}
	closedPorts := []int{}

	for port := port1; port <= port2; port++ {
		result := <-results
		if result.status == "Açık" {
			openPorts = append(openPorts, result.port)
		} else {
			closedPorts = append(closedPorts, result.port)
		}
	}

	close(results)

	fmt.Println("Açık portlar:")
	for _, port := range openPorts {
		fmt.Printf("%d\n", port)
	}

	if kapalıChoice == 1 {
		fmt.Println("Kapalı portlar:")
		for _, port := range closedPorts {
			fmt.Printf("%d\n", port)
		}
	}

    fmt.Println("Tarama tamamlandı.")
}
