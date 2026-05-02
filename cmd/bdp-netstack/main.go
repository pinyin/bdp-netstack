// bdp-netstack is a BDP-based user-space TCP/IP network stack for vfkit VMs.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/pinyin/bdp-netstack/pkg/fwd"
	"github.com/pinyin/bdp-netstack/pkg/stack"
	"github.com/pinyin/bdp-netstack/pkg/tcp"
)

func main() {
	socketPath := flag.String("socket", "/tmp/bdp-stack.sock", "vfkit unixgram socket path")
	gatewayIP := flag.String("gateway-ip", "192.168.65.1", "gateway IP address")
	gatewayMAC := flag.String("gateway-mac", "5a:94:ef:e4:0c:ee", "gateway MAC address")
	subnetCIDR := flag.String("subnet", "192.168.65.0/24", "subnet CIDR")
	bpt := flag.Duration("bpt", 1*time.Millisecond, "batch processing tick (BPT)")
	mtu := flag.Int("mtu", 1500, "MTU")
	bufSize := flag.Int("buf-size", 524288, "TCP buffer size (512KB)")
	debug := flag.Bool("debug", false, "enable debug logging")
	flag.Parse()

	// Parse port forwards from remaining args: hostPort:vmIP:vmPort
	var forwards []fwd.Mapping
	for _, arg := range flag.Args() {
		parts := strings.Split(arg, ":")
		if len(parts) != 3 {
			log.Fatalf("invalid forward spec %q (expected hostPort:vmIP:vmPort)", arg)
		}
		hostPort, err := strconv.Atoi(parts[0])
		if err != nil {
			log.Fatalf("invalid host port in forward spec %q: %v", arg, err)
		}
		vmIP := net.ParseIP(parts[1])
		if vmIP == nil {
			log.Fatalf("invalid VM IP in forward spec %q: %s", arg, parts[1])
		}
		vmPort, err := strconv.Atoi(parts[2])
		if err != nil {
			log.Fatalf("invalid VM port in forward spec %q: %v", arg, err)
		}
		forwards = append(forwards, fwd.Mapping{
			HostPort: uint16(hostPort),
			VMIP:     vmIP,
			VMPort:   uint16(vmPort),
		})
	}

	mac, err := net.ParseMAC(*gatewayMAC)
	if err != nil {
		log.Fatalf("invalid gateway MAC: %v", err)
	}

	gwIP := net.ParseIP(*gatewayIP)
	if gwIP == nil {
		log.Fatalf("invalid gateway IP: %s", *gatewayIP)
	}

	cfg := stack.Config{
		SocketPath:   *socketPath,
		GatewayMAC:   mac,
		GatewayIP:    gwIP,
		SubnetCIDR:   *subnetCIDR,
		MTU:          *mtu,
		BPT:          *bpt,
		TCPBufSize:   *bufSize,
		PortForwards: forwards,
		Debug:        *debug,
	}

	tcpCfg := tcp.DefaultConfig()
	tcpCfg.ListenPort = 0 // no listener by default
	tcpCfg.GatewayIP = gwIP
	tcpCfg.BufferSize = *bufSize
	tcpCfg.MTU = *mtu - 20 // IP payload max (TCP segment = MTU - IP header)
	tcpCfg.BPT = *bpt

	ts := tcp.NewTCPState(tcpCfg)

	s := stack.New(cfg, ts)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("received signal %v, shutting down", sig)
		cancel()
	}()

	log.Printf("BDP netstack starting: %s on %s (BPT=%v)", *gatewayIP, *socketPath, *bpt)

	if err := s.Run(ctx); err != nil {
		if err == context.Canceled {
			log.Println("netstack stopped")
		} else {
			fmt.Fprintf(os.Stderr, "netstack error: %v\n", err)
			os.Exit(1)
		}
	}
}
