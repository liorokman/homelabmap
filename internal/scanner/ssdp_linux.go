//go:build linux

package scanner

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

// setMulticastIface sends the search out of the LAN interface rather than
// wherever the multicast route points (often a Docker bridge).
func setMulticastIface(conn net.PacketConn, iface string) error {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return err
	}
	uc, ok := conn.(*net.UDPConn)
	if !ok {
		return errors.New("not a UDP socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	err = raw.Control(func(fd uintptr) {
		serr = unix.SetsockoptIPMreqn(int(fd), unix.IPPROTO_IP, unix.IP_MULTICAST_IF, &unix.IPMreqn{Ifindex: int32(ifi.Index)})
	})
	return errors.Join(err, serr)
}
