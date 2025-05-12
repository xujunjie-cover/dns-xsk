package dns_xsk

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/slavc/xdp"

	"github.com/xujunjie-cover/dns-xsk/pkg/bpf"
)

func Attach(linkName string, maxQueue int) {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	interfaces, err := net.Interfaces()
	if err != nil {
		fmt.Printf("error: failed to fetch the list of network interfaces on the system: %v\n", err)
		return
	}

	Ifindex := -1
	for _, iface := range interfaces {
		if iface.Name == linkName {
			Ifindex = iface.Index
			break
		}
	}
	if Ifindex == -1 {
		fmt.Printf("error: couldn't find a suitable network interface to attach to\n")
		return
	}

	object := bpf.GetBpfObj()

	// var program *xdp.Program
	program := &xdp.Program{
		Program: object.XdpSockProg,
		Queues:  object.QidconfMap,
		Sockets: object.XsksMap,
	}

	// Create a new XDP eBPF program and attach it to our chosen network link.
	// if protocol == 0 {
	// 	program, err = xdp.NewProgram(queueID + 1)
	// } else {
	// 	program, err = ebpf.NewIPProtoProgram(uint32(protocol), nil)
	// }
	defer program.Close()
	if err := program.Attach(Ifindex); err != nil {
		fmt.Printf("error: failed to attach xdp program to interface: %v\n", err)
		return
	}
	defer program.Detach(Ifindex)

	// Create and initialize an XDP socket attached to our chosen network
	// link.

	for i := 0; i < maxQueue; i++ {
		go func(queueID int) {
			fmt.Printf("creating XDP socket for queueId %d\n", queueID)
			xsk, err := xdp.NewSocket(Ifindex, queueID, nil)
			if err != nil {
				fmt.Printf("error: failed to create an XDP socket: %v\n", err)
				return
			}

			fmt.Printf("queueId %d, fd %d", queueID, xsk.FD())
			// Register our XDP socket file descriptor with the eBPF program so it can be redirected packets
			if err := program.Register(queueID, xsk.FD()); err != nil {
				fmt.Printf("error: failed to register socket in BPF map: %v\n", err)
				return
			}
			defer program.Unregister(queueID)
		
			for {
				// If there are any free slots on the Fill queue...
				if n := xsk.NumFreeFillSlots(); n > 0 {
					// ...then fetch up to that number of not-in-use
					// descriptors and push them onto the Fill ring queue
					// for the kernel to fill them with the received
					// frames.
					xsk.Fill(xsk.GetDescs(n, true))
				}
		
				// Wait for receive - meaning the kernel has
				// produced one or more descriptors filled with a received
				// frame onto the Rx ring queue.
				log.Printf("waiting for frame(s) to be received...")
				numRx, _, err := xsk.Poll(-1)
				if err != nil {
					fmt.Printf("error: %v\n", err)
					return
				}
		
				fmt.Printf("received %d frame(s)\n", numRx)
		
				if numRx > 0 {
					// Consume the descriptors filled with received frames
					// from the Rx ring queue.
					rxDescs := xsk.Receive(numRx)
		
					// Print the received frames and also modify them
					// in-place replacing the destination MAC address with
					// broadcast address.
					for i := 0; i < len(rxDescs); i++ {
						pktData := xsk.GetFrame(rxDescs[i])
						pkt := gopacket.NewPacket(pktData, layers.LayerTypeEthernet, gopacket.Default)
						log.Printf("received frame:\n%s%+v", hex.Dump(pktData[:]), pkt)
					}
				}
			}
		}(i)
	}

	time.Sleep(10 * time.Minute)
}
