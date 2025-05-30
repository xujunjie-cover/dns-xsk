package main

import (
	"context"
	"fmt"

	dns_xsk "github.com/xujunjie-cover/dns-xsk"
)


func main() {
	packetChan := make(chan []byte)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dns_xsk.Attach("eth0", 63, packetChan, ctx)

	for {
		select {
		case packet := <-packetChan:
			// Process the packet
			fmt.Println(packet)
		case <-ctx.Done():
			return
		}
	}
}
