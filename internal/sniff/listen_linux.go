//go:build linux

package sniff

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

// ndpFilter is a classic BPF program that accepts only ICMPv6 types
// 133-136 (router/neighbour solicitation and advertisement), so the IPv6
// socket doesn't copy the host's ordinary IPv6 traffic to user space.
//
//	0: ldb [20]          ; IPv6 next header
//	1: jeq #58, 2, 6     ; ICMPv6?
//	2: ldb [54]          ; ICMPv6 type
//	3: jge #133, 4, 6
//	4: jgt #136, 6, 5
//	5: ret #65535
//	6: ret #0
var ndpFilter = []unix.SockFilter{
	{Code: 0x30, K: 20},
	{Code: 0x15, Jt: 0, Jf: 4, K: 58},
	{Code: 0x30, K: 54},
	{Code: 0x35, Jt: 0, Jf: 2, K: ndpRS},
	{Code: 0x25, Jt: 1, Jf: 0, K: ndpNA},
	{Code: 0x06, K: 0xffff},
	{Code: 0x06, K: 0},
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// Listen reads ARP and NDP on iface until ctx ends, calling emit for each
// sighting. Frames the host sends itself are ignored. It needs CAP_NET_RAW.
func Listen(ctx context.Context, iface string, emit func(Sighting)) error {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return err
	}
	arp, err := openPacket(ifi.Index, etherARP, nil, false)
	if err != nil {
		return fmt.Errorf("ARP socket: %w", err)
	}
	defer unix.Close(arp)
	// All-multicast: NDP goes to solicited-node groups this host hasn't joined.
	v6, err := openPacket(ifi.Index, etherIPv6, ndpFilter, true)
	if err != nil {
		return fmt.Errorf("IPv6 socket: %w", err)
	}
	defer unix.Close(v6)

	// Stop both readers when either fails, and return only after both have
	// stopped calling emit.
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errc := make(chan error, 2)
	for _, fd := range []int{arp, v6} {
		go func() {
			err := readLoop(rctx, fd, emit)
			cancel()
			errc <- err
		}()
	}
	err = errors.Join(<-errc, <-errc)
	if ctx.Err() != nil {
		return nil
	}
	return err
}

func openPacket(ifindex int, proto uint16, filter []unix.SockFilter, allmulti bool) (int, error) {
	if ifindex <= 0 || ifindex > math.MaxInt32 || len(filter) > math.MaxUint16 {
		return -1, fmt.Errorf("interface index %d or filter length %d out of range", ifindex, len(filter))
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(proto)))
	if err != nil {
		return -1, err
	}
	fail := func(err error) (int, error) { _ = unix.Close(fd); return -1, err }
	if filter != nil {
		prog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]} //nolint:gosec // range-checked above
		if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &prog); err != nil {
			return fail(fmt.Errorf("attaching filter: %w", err))
		}
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(proto), Ifindex: ifindex}); err != nil {
		return fail(err)
	}
	if allmulti {
		mreq := unix.PacketMreq{Ifindex: int32(ifindex), Type: unix.PACKET_MR_ALLMULTI} //nolint:gosec // range-checked above
		if err := unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &mreq); err != nil {
			return fail(fmt.Errorf("all-multicast: %w", err))
		}
	}
	// A receive timeout lets the loop notice cancellation.
	tv := unix.NsecToTimeval(time.Second.Nanoseconds())
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return fail(err)
	}
	return fd, nil
}

func readLoop(ctx context.Context, fd int, emit func(Sighting)) error {
	buf := make([]byte, 2048)
	for ctx.Err() == nil {
		n, from, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				continue
			}
			return err
		}
		if ll, ok := from.(*unix.SockaddrLinklayer); ok && ll.Pkttype == unix.PACKET_OUTGOING {
			continue
		}
		if s, ok := Parse(buf[:n]); ok {
			emit(s)
		}
	}
	return nil
}
