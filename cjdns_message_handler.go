package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"strconv"
	"time"

	"github.com/zeebo/bencode"
)

const (
	ContentType_IP6_IP       = 0
	ContentType_IP6_ICMP     = 1
	ContentType_IP6_IGMP     = 2
	ContentType_IP6_IPIP     = 4
	ContentType_IP6_TCP      = 6
	ContentType_IP6_EGP      = 8
	ContentType_IP6_PUP      = 12
	ContentType_IP6_UDP      = 17
	ContentType_IP6_IDP      = 22
	ContentType_IP6_TP       = 29
	ContentType_IP6_DCCP     = 33
	ContentType_IP6_IPV6     = 41
	ContentType_IP6_RSVP     = 46
	ContentType_IP6_GRE      = 47
	ContentType_IP6_ESP      = 50
	ContentType_IP6_AH       = 51
	ContentType_IP6_MTP      = 92
	ContentType_IP6_BEETPH   = 94
	ContentType_IP6_ENCAP    = 98
	ContentType_IP6_PIM      = 103
	ContentType_IP6_COMP     = 108
	ContentType_IP6_SCTP     = 132
	ContentType_IP6_UDPLITE  = 136
	ContentType_IP6_RAW      = 255
	ContentType_CJDHT        = 256
	ContentType_IPTUN        = 257
	ContentType_RESERVED     = 258
	ContentType_RESERVED_MAX = 0x7fff
	ContentType_AVAILABLE    = 0x8000
	ContentType_CTRL         = 0xffff + 1
	ContentType_MAX          = 0xffff + 2
)

type Cjdns struct {
	SocketPath string
	Socket     net.Conn
	Device     string
	IPv6       string
}

var cjdns Cjdns

// Connect to CJDNS socket
func Init() error {
	conn, err := net.Dial("unix", cjdns.SocketPath)
	if err != nil {
		return err
	}
	cjdns.Socket = conn
	return nil
}

// Close CJDNS socket
func Close(ls net.Conn) error {
	err := ls.Close()
	if err != nil {
		return err
	}
	return nil
}

func pingListener() (string, error) {
	cjdns.Socket.SetReadDeadline(time.Now().Add(1 * time.Second))
	buf := make([]byte, 1024)
	n, err := cjdns.Socket.Read(buf)

	var response map[string]interface{}
	if n > 0 {
		err := bencode.DecodeBytes(buf, &response)
		if err != nil {
			return "", err
		}
		// check if response has "addr" and "ms" fields
		if addr, ok := response["addr"].(string); ok {
			res := addr + " ms:" + fmt.Sprintf("%d", response["ms"].(int64))
			return res, nil
		} else if q, ok := response["q"].(string); ok && q == "pong" {
			return q, nil
		}
		return "", nil
	}
	if e, ok := err.(interface{ Timeout() bool }); ok && e.Timeout() {
		return "", errors.New("CJDNS connection timeout")
	} else if err != nil {
		return "", err
	}
	return "", nil
}

func registerHandler(contentType int64, udpPort int64) error {
	message := map[string]interface{}{
		"q":    "UpperDistributor_registerHandler",
		"args": map[string]int64{"contentType": contentType, "udpPort": udpPort},
	}
	fmt.Println("Message:", message)
	bytes, err := bencode.EncodeBytes(message)
	if err != nil {
		return err
	}
	_, err = cjdns.Socket.Write(bytes)
	if err != nil {
		return err
	}
	return nil
}

func unregisterHandler(udpPort int64) error {
	message := map[string]interface{}{
		"q":    "UpperDistributor_unregisterHandler",
		"args": map[string]int64{"udpPort": udpPort},
	}
	bytes, err := bencode.EncodeBytes(message)
	if err != nil {
		return err
	}
	_, err = cjdns.Socket.Write(bytes)
	if err != nil {
		return err
	}
	return nil
}

func getDeviceAddr(device string) (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		fmt.Println("Error getting interfaces:", err)
		return "", err
	}
	deviceAddr := ""
	for _, iface := range ifaces {
		if iface.Name == device {
			addrs, err := iface.Addrs()
			if err != nil {
				fmt.Println("Error getting addresses for tun0:", err)
				return "", err
			}

			for _, addr := range addrs {
				fmt.Println("Address:", addr)
				ip, _, err := net.ParseCIDR(addr.String())
				if err != nil {
					fmt.Println("Error parsing CIDR:", err)
					return "", err
				}
				deviceAddr = ip.String()
				break
			}
		}
		if deviceAddr != "" {
			return deviceAddr, nil
		}
	}
	return "", errors.New("device not found")
}

func sendCjdnsMessage(cjdns_addr string, pubkey string, amount int) error {
	fmt.Println("Send Cjdns message to:", cjdns_addr, "pubkey:", pubkey, "amount:", amount)
	// use this to send a packet to cjdns throught tun0
	rAddr, err := net.ResolveUDPAddr("udp", "[fc00::1]:1")
	if err != nil {
		fmt.Println("Error resolving UDP address:", err)
		return err
	}
	cjdns.IPv6, err = getDeviceAddr(cjdns.Device)
	if err != nil {
		fmt.Println("Error getting device address:", err)
		return err
	}
	//bind to local address (tun0) and a port, then register that port to cjdns
	sAddr := &net.UDPAddr{IP: net.ParseIP(cjdns.IPv6), Port: 37193}
	conn, err := net.DialUDP("udp", sAddr, rAddr)
	
	registerHandler(ContentType_RESERVED, 37193)
	if err != nil {
		fmt.Println("Error dialing UDP address:", err)
		return err
	}
	defer conn.Close()

	// Data to send
	// receiverPubkey := "pvt7n9bt2s3jcl52glw1b06ruyg93y3qn4lfm9590ptjvxr90hj0.k"
	// receiverIP := "fce3:86e9:b183:1a06:ad9a:c37f:14fe:36c2"
	data := createInvoiceRequest(cjdns_addr, pubkey, amount)
	// Send data
	_, err = conn.Write(data)
	if err != nil {
		fmt.Println("Error sending UDP packet:", err)
		unregisterHandler(37193)
		return err
	}

	fmt.Println("UDP packet sent successfully")
	unregisterHandler(37193)
	return nil
}

func ListeningForInvoiceRequest(cjdnsaddr string) error {
	// use this to read a packet to cjdns throught tun0
	cjdns.IPv6, _ = getDeviceAddr(cjdns.Device)
	rAddr, err := net.ResolveUDPAddr("udp", "["+cjdnsaddr+"]:0")
	fmt.Println("ListeningForInvoiceRequest:", rAddr)
	if err != nil {
		fmt.Println("Error resolving UDP address:", err)
		return err
	}

	//bind to local address (tun0) and a port, then register that port to cjdns
	fmt.Println("Port:", rAddr.Port)
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(cjdnsaddr), Port: rAddr.Port})
	if err != nil {
		fmt.Println("Error dialing UDP address:", err)
		return err
	}
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	registerHandler(ContentType_RESERVED, int64(localAddr.Port))
	buf := make([]byte, 1024)
	// go func() {
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				fmt.Printf("Error reading from UDP port %d: %v\n", rAddr.Port, err)
				continue
			}
			fmt.Printf("Received %d bytes from %s: %s\n", n, addr.String(), string(buf[:n]))
			message, err := decode(buf[:n])
			if err != nil {
				fmt.Println(err)
				continue
			}
			if message.DataHeader.ContentType == ContentType_RESERVED {
				fmt.Println("Received RESERVED message")

				if message.ContentBenc.(map[string]interface{})["q"] != nil && message.ContentBenc.(map[string]interface{})["q"].(string) == "invoice_req" {
					fmt.Println("Received request")
					// Decode request

				}
			}
		}
	// }()
	//unregisterHandler(int64(localAddr.Port))
	// return nil
}


func generateRandomNumber() int {
    rand.Seed(time.Now().UnixNano())
    return rand.Intn(9000000000) + 1000000000
}

func createInvoiceRequest(receiverIP string, receiverPubkey string, amount int) []byte {
	// Set the application layer payload
	coinType := []byte{0x80, 0x00, 0x01, 0x86}
	var bytesMessage []byte = nil
	txid := generateRandomNumber()
	msg := map[string]interface{}{
		"q":    "invoice_req",
		"amt":  amount,
		"txid": strconv.Itoa(txid)+"/0",
	}

	bytesMessage = append(bytesMessage, coinType...)
	encodedMsg, err := bencode.EncodeBytes(msg)
	if err != nil {
		fmt.Println("Error encoding message:", err)
	}
	bytesMessage = append(bytesMessage, encodedMsg...)
	var cjdnsip net.IP = net.ParseIP(receiverIP)
	var message Message = Message{
		RouteHeader: RouteHeader{
			PublicKey: receiverPubkey,
			Version:   22,
			IP:        cjdnsip,
			SwitchHeader: SwitchHeader{
				Label:   "0000",
				Version: 1,
			},
			IsIncoming: false,
			IsCtrl:     false,
		},
		DataHeader: DataHeader{
			ContentType: ContentType_RESERVED,
			Version:     1,
		},
		ContentBytes: bytesMessage,
		RawBytes:     nil,
		ContentBenc:  msg,
		Content:      nil,
	}
	fmt.Println("Bencode content:", msg)
	payload, err := message.encode()
	if err != nil {
		fmt.Println("Error encoding message:", err)
	}
	return payload
}

func ping(node string) (string, error) {
	fmt.Println("Ping Cjdns node:", node)
	err := error(nil)
	if cjdns.Socket == nil {
		return "", errors.New("CJDNS connection is nil")
	}

	ping := map[string]string{
		"q": "ping",
	}
	pingNode := map[string]interface{}{
		"q":    "RouterModule_pingNode",
		"args": map[string]string{"path": "fc93:1145:f24c:ee59:4a09:288e:ada8:0901"},
	}
	var bytes []byte
	if node != "" {
		bytes, err = bencode.EncodeBytes(pingNode)
		if err != nil {
			return "", err
		}
	} else {
		bytes, err = bencode.EncodeBytes(ping)
		if err != nil {
			return "", err
		}
	}

	_, err = cjdns.Socket.Write(bytes)
	if err != nil {
		return "", err
	}
	data, err := pingListener()
	if err != nil {
		return "", err
	}

	return data, nil
}

func readConfig() {
	configFile, err := ioutil.ReadFile("config.json")
    if err != nil {
        panic(err)
    }

    var config struct {
        Cjdns Cjdns `json:"cjdns"`
    }
    err = json.Unmarshal(configFile, &config)
    if err != nil {
        panic(err)
    }

    // Set the Cjdns struct
    cjdns = config.Cjdns
}

func main() {    
	readConfig()

	err := Init()
	if err != nil {
		fmt.Println(err)
	}

	var udpPort int64 = 1
	registerHandler(ContentType_RESERVED, udpPort)	

	// check for --send parameter
	sendPtr := flag.Bool("send", false, "a bool")
	pingPtr := flag.Bool("ping", false, "a bool")
    cjdnsaddrPtr := flag.String("cjdnsaddr", "", "The cjdnsaddr to use.")
    pubkeyPtr := flag.String("pubkey", "", "The pubkey to use.")
    amountPtr := flag.Int("amount", 0, "The amount to use.")

    // Parse the command line flags.
    flag.Parse()

	if *sendPtr {
		sendCjdnsMessage(*cjdnsaddrPtr, *pubkeyPtr, *amountPtr)
	} else {
		err := ListeningForInvoiceRequest(*cjdnsaddrPtr)
		if err != nil {
			fmt.Println(err)
			return
		}
	}
	if *pingPtr {
		// vm cjdns node fce3:86e9:b183:1a06:ad9a:c37f:14fe:36c2
		data, err := ping("fce3:86e9:b183:1a06:ad9a:c37f:14fe:36c2")
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println(data)
	}
	fmt.Println("Press enter to exit...")
	fmt.Scanln()

	unregisterHandler(udpPort)
}
