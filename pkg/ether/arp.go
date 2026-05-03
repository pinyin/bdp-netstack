package ether

import (
	"net"
)

// ARPResolver maintains the ARP table (IP → MAC).
// In the single-VM case, the table is trivial — just the VM's IP→MAC mapping.
type ARPResolver struct {
	table map[string]net.HardwareAddr // IP string → MAC
}

func NewARPResolver() *ARPResolver {
	return &ARPResolver{
		table: make(map[string]net.HardwareAddr),
	}
}

func (a *ARPResolver) Lookup(ip net.IP) (net.HardwareAddr, bool) {
	mac, ok := a.table[ip.String()]
	return mac, ok
}

func (a *ARPResolver) Set(ip net.IP, mac net.HardwareAddr) {
	macCopy := make(net.HardwareAddr, len(mac))
	copy(macCopy, mac)
	a.table[ip.String()] = macCopy
}
