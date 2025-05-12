package bpf

import (
	"fmt"
	"os"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

const (
	pinPath    = "/sys/fs/bpf/dns-xsk"
)

var objs *dnsObjects
var once sync.Once

func GetBpfObj() *dnsObjects {
	once.Do(func() {
		err := rlimit.RemoveMemlock()
		if err != nil {
			os.Exit(1)
		}
		err = os.MkdirAll(pinPath, os.ModeDir)
		if err != nil {
			os.Exit(1)
		}

		// err = features.HaveProgramHelper(ebpf.SchedCLS, asm.FnSkbEcnSetCe)
		// if err != nil {
		// 	if !errors.Is(err, ebpf.ErrNotSupported) {
		// 		os.Exit(1)
		// 	}
		// }

		objs = &dnsObjects{}

		opts := &ebpf.CollectionOptions{
			Maps: ebpf.MapOptions{
				PinPath:        pinPath,
				LoadPinOptions: ebpf.LoadPinOptions{},
			},
			Programs:        ebpf.ProgramOptions{},
			MapReplacements: nil,
		}


		err = loadDnsObjects(objs, opts)
		if err != nil {
			fmt.Printf("error: failed to load dns objects: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("success: loaded dns objects\n")

	})
	return objs
}