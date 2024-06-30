package main
//Root/Administrator or Administrator permission required
import (
	"fmt"
	"log"
	"net"
	"sync"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func main() {
	targetIP := "192.168.1.1"
	localIP := "192.168.1.34"
	var wg sync.WaitGroup
	portChan := make(chan int)

	for port := 1; port <= 65535; port++ { 
		wg.Add(1)
		go tcpAckScan(&wg, targetIP, localIP, port, portChan)
	}

	go func() {
		for port := range portChan {
			fmt.Printf("Port %d is open\n", port)
		}
	}()

	wg.Wait()
	close(portChan)
}

func tcpAckScan(wg *sync.WaitGroup, targetIP, localIP string, port int, portChan chan int) {
	defer wg.Done()

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

	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(port),
		DstPort: layers.TCPPort(port),
		Seq:     0,
		Window:  30600,
		ACK:     true,
	}


	if err := tcpLayer.SetNetworkLayerForChecksum(ipLayer); err != nil {
		log.Printf("Failed to set network layer for checksum: %v\n", err)
		return
	}

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err := gopacket.SerializeLayers(buffer, opts, ipLayer, tcpLayer)
	if err != nil {
		log.Printf("Failed to serialize packet for port %d: %v\n", port, err)
		return
	}
	packetData := buffer.Bytes()

	conn, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_IP) 
	if err != nil {
		log.Printf("Failed to create raw socket: %v\n", err)
		return
	}
	defer syscall.Close(conn)

	var dstAddr syscall.SockaddrInet4
	copy(dstAddr.Addr[:], net.ParseIP(targetIP).To4())

	err = syscall.Sendto(conn, packetData, 0, &dstAddr)
	if err != nil {
		log.Printf("Failed to send packet for port %d: %v\n", port, err)
		return
	}

	// Listen for responses
	var listenWG sync.WaitGroup
	listenWG.Add(1)
	go listenResponse(conn, port, portChan, &listenWG)

	listenWG.Wait()
}

func listenResponse(conn syscall.Handle, port int, portChan chan int, wg *sync.WaitGroup) {
	defer wg.Done()
	buffer := make([]byte, 2048)

	for {
		n, _, err := syscall.Recvfrom(conn, buffer, 0)
		if err != nil {
			log.Printf("Failed to receive response for port %d: %v\n", port, err)
			return
		}

		fmt.Printf("Received response on port %d: %s\n", port, buffer[:n])

		if n > 0 {
			portChan <- port
			return
		}
	}
}
