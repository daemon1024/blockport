package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"

	bpf "github.com/iovisor/gobpf/bcc"
)

/*
#cgo CFLAGS: -I/usr/include/bcc/compat
#cgo LDFLAGS: -lbcc
#include <bcc/bcc_common.h>
#include <bcc/libbpf.h>
void perf_reader_free(void *ptr);
*/
import "C"

const source string = `
#define KBUILD_MODNAME "blockport"
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <uapi/linux/bpf.h>

int tcpfilter(struct CTXTYPE *ctx) {

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;

	// Byte-count bounds check; check if current pointer + size of header is before data_end.
	if ((void*)eth + sizeof(*eth) <= data_end) {
	  	struct iphdr *ip = data + sizeof(*eth);
	  	if ((void*)ip + sizeof(*ip) <= data_end) {
		
			//Checking if the protocol with TCP Protocal
			if (ip->protocol == IPPROTO_TCP) {
				struct tcphdr *tcp = (void*)ip + sizeof(*ip);
				if ((void*)tcp + sizeof(*tcp) <= data_end) {

					//Checking if the destination port matches with the specified port
					if (tcp->dest == ntohs(PORT)) {

						//Drop Packet
						return RETURNCODE;
					}
				}
			}
	  	}
	}
	return XDP_PASS;
}
`

func main() {
	var device string
	var port string

	flag.StringVar(&device, "device", "lo", "Network device to attach XDP program to")
	flag.StringVar(&port, "port", "", "Port number to block incoming tcp packets at")

	flag.Parse()

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: sudo blockport [--device] <network-device> [--port] <port-number>\n")
		flag.PrintDefaults()
	}

	if port == "" {
		flag.Usage()
		os.Exit(1)
	}

	ret := "XDP_DROP"
	ctxtype := "xdp_md"

	module := bpf.NewModule(source, []string{
		"-w",
		"-DRETURNCODE=" + ret,
		"-DCTXTYPE=" + ctxtype,
		"-DPORT=" + port,
	})
	defer module.Close()

	fn, err := module.Load("tcpfilter", C.BPF_PROG_TYPE_XDP, 1, 65536)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load xdp prog: %v\n", err)
		os.Exit(1)
	}

	err = module.AttachXDP(device, fn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach xdp prog: %v\n", err)
		os.Exit(1)
	}

	defer func() {
		if err := module.RemoveXDP(device); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to remove XDP from %s: %v\n", device, err)
		}
	}()

	fmt.Printf("Dropping TCP packets at port %s, hit CTRL+C to stop", port)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	<-sig
}
