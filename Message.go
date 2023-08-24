package main

import (
	// "encoding/hex"
	"bytes"
	// "encoding/hex"
	"fmt"

	"github.com/zeebo/bencode"
)

type Message struct {
	RouteHeader  RouteHeader
	DataHeader   DataHeader
	ContentBytes []byte
	RawBytes     []byte
	ContentBenc  interface{}
	Content      interface{}
}

func (msg* Message) encode() ([]byte, error) {
    var buf bytes.Buffer

    // Write route header
    routeHeaderBytes, err := msg.RouteHeader.serialize()
	// fmt.Println("Route Header Bytes:", routeHeaderBytes)
    if err != nil {
        return nil, err
    }
    buf.Write(routeHeaderBytes)

    // Write data header if not a control message
    if !msg.RouteHeader.IsCtrl {
        //dataHeaderBytes, err := msg.DataHeader.encode()
		
		dataHeaderBytes, err := msg.DataHeader.encode()
        if err != nil {
            return nil, err
        }
        buf.Write(dataHeaderBytes)
    }

    // Write content bytes
    buf.Write(msg.ContentBytes)

    return buf.Bytes(), nil
}

func decode(bytes []byte) (Message, error) {
	x := 0
	routeHeaderBytes := bytes[x:RouteHeaderSize]
	// fmt.Println("Route Header Bytes:", routeHeaderBytes)
	x += RouteHeaderSize
	routeHeader := RouteHeader{}
	routeHeader, err := routeHeader.parse(routeHeaderBytes)
	if err != nil {
		fmt.Println("Error parsing route header: ", err)
	}

	// fmt.Println("Route Header:", routeHeader)
	// fmt.Println("IsCTRL:", routeHeader.IsCtrl)
	var dataHeaderBytes []byte = nil
	var dataHeader DataHeader = DataHeader{}
	if !routeHeader.IsCtrl {
		dataHeaderBytes = bytes[x : x+DataHeaderSize]
		x += DataHeaderSize
		dataHeader, err = dataHeader.parse(dataHeaderBytes)
		if err != nil {
			fmt.Println("Error parsing data header: ", err)
		}
		//fmt.Println("Data Header:", dataHeader)
	}
	dataBytes := bytes[x:]
	var decodedBytes interface{} = nil
	var content interface{} = nil
	if dataHeader.ContentType == 258 {
		// fmt.Println("Bytes:", string(dataBytes))
		// hexStr := hex.EncodeToString(dataBytes)
		// fmt.Println("Hex:", hexStr)
		bencode.DecodeBytes(dataBytes, &decodedBytes)
		// fmt.Println("Decoded Bytes:", decodedBytes)
		//get and print txid from decoded bytes
		// txid := decodedBytes.(map[string]interface{})["txid"]
		// fmt.Println("txid:", txid)
	} else if routeHeader.IsCtrl {
		content, _ = parseCtrl(dataBytes)
	}

	return Message{
		RouteHeader:  routeHeader,
		DataHeader:   dataHeader,
		ContentBytes: dataBytes,
		RawBytes:     bytes,
		ContentBenc:  decodedBytes,
		Content:      content,
	}, nil
}
