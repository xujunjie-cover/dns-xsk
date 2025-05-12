package main

import (
	dns_xsk "github.com/xujunjie-cover/dns-xsk"
)


func main() {

	dns_xsk.Attach("ens256", 1)
}
