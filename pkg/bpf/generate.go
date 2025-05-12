package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -strip $BPF_STRIP dns ../../ebpf/dns.c -- -I../../ebpf/headers
