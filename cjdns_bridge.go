package main

import (
	"fmt"
	"net"
	"time"
	//"github.com/jackpal/bencode-go"
)

const (
	socketPath string = "/home/dimitris/cjdroute.sock"
)

func Init() (net.Conn, error) {
	// Connect to the Unix socket
	fmt.Println("Connecting to: ", socketPath)
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// func listener(ls net.Conn, ch chan string) {
// 	fmt.Println("Listening...")
// 	buf := make([]byte, 1024)
// 	for {
// 		n, err := ls.Read(buf)
// 		if err != nil {
// 			fmt.Println("Read error:", err)
// 			break
// 		}
// 		data := string(buf[:n])
// 		fmt.Println("Received data:", data)
// 		ch <- data
// 	}
// }

func GetData(ls net.Conn) (string, error) {
	ls.SetReadDeadline(time.Now().Add(1 * time.Second))
	buf := make([]byte, 1024)
	n, err := ls.Read(buf)
	fmt.Println("Read...")
	if n > 0 {
		data := string(buf[:n])
		fmt.Println("Received data:", data)
		return data, nil
	}
	if e, ok := err.(interface{ Timeout() bool }); ok && e.Timeout() {
		fmt.Println("Timeout...")
		return "", nil
	} else if err != nil {
		fmt.Println("Error:", err)
		return "", err
	}
	return "", nil
}

func Ping(ls net.Conn) (string, error) {
	fmt.Println("Ping...")
	err := error(nil)
	if ls == nil {
		ls, err = Init()
		if err != nil {
			return "", err
		}
	}
	defer ls.Close()

	fmt.Println("Sending ping...")
	_, err = ls.Write([]byte("d1:q4:ping"))
	if err != nil {
		fmt.Println("Write error:", err)
		return "", err
	}
	data, err := GetData(ls)
	if err != nil {
		fmt.Println("GetData error:", err)
		return "", err
	}

	return data, nil
}

func main() {
	ls, err := Init()
	if err != nil {
		fmt.Println("Init error:", err)
	}
	res, errr := Ping(ls)
	if errr != nil {
		fmt.Println("Ping error:", errr)
	}
	fmt.Println("Ping result:", res)
}
