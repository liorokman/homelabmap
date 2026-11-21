//go:build !linux

package scanner

import "net"

func setMulticastIface(net.PacketConn, string) error { return nil }
