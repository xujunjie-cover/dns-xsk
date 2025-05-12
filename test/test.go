package main

import (
	dns_xsk "github.com/xujunjie-cover/dns-xsk"
)


func main() {
	packetChan := make(chan []byte)
	dns_xsk.Attach("ens256", 1, packetChan)
}
