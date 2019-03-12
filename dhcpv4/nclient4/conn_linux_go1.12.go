// Copyright 2018 the u-root Authors and Andrea Barberio. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build linux,go1.12

package nclient4

import (
	"fmt"
	"io"
	"net"

	"github.com/mdlayher/ethernet"
	"github.com/mdlayher/raw"
	"github.com/u-root/u-root/pkg/uio"
)

var (
	// BroadcastMac is the broadcast MAC address.
	//
	// Any UDP packet sent to this address is broadcast on the subnet.
	BroadcastMac = net.HardwareAddr([]byte{255, 255, 255, 255, 255, 255})
)

// New returns a client usable with an unconfigured interface.
func New(ifaceName string, ifaceHWAddr net.HardwareAddr, opts ...ClientOpt) (*Client, error) {
	c, err := NewWithConn(nil, ifaceHWAddr, opts...)
	if err != nil {
		return nil, err
	}

	// Do this after so that a caller can still use a WithConn to override
	// the connection.
	if c.conn == nil {
		pc, err := NewRawUDPConn(ifaceName, ClientPort)
		if err != nil {
			return nil, err
		}
		c.conn = pc
	}
	return c, nil
}

// NewRawUDPConn returns a UDP connection bound to the interface and port
// given based on a raw packet socket. All packets are broadcasted.
func NewRawUDPConn(iface string, port int) (net.PacketConn, error) {
	ifc, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, err
	}
	rawConn, err := raw.ListenPacket(ifc, uint16(ethernet.EtherTypeIPv4), &raw.Config{LinuxSockDGRAM: true})
	if err != nil {
		return nil, err
	}
	return NewBroadcastUDPConn(rawConn, &net.UDPAddr{Port: port}), nil
}

// BroadcastRawUDPConn uses a raw socket to send UDP packets to the broadcast
// MAC address.
type BroadcastRawUDPConn struct {
	// PacketConn is a raw DGRAM socket.
	net.PacketConn

	// boundAddr is the address this RawUDPConn is "bound" to.
	//
	// Calls to ReadFrom will only return packets destined to this address.
	boundAddr *net.UDPAddr
}

// NewBroadcastUDPConn returns a PacketConn that marshals and unmarshals UDP
// packets, sending them to the broadcast MAC at on rawPacketConn.
//
// Calls to ReadFrom will only return packets destined to boundAddr.
func NewBroadcastUDPConn(rawPacketConn net.PacketConn, boundAddr *net.UDPAddr) net.PacketConn {
	return &BroadcastRawUDPConn{
		PacketConn: rawPacketConn,
		boundAddr:  boundAddr,
	}
}

func udpMatch(addr *net.UDPAddr, bound *net.UDPAddr) bool {
	if bound == nil {
		return true
	}
	if bound.IP != nil && !bound.IP.Equal(addr.IP) {
		return false
	}
	return bound.Port == addr.Port
}

// ReadFrom implements net.PacketConn.ReadFrom.
//
// ReadFrom reads raw IP packets and will try to match them against
// upc.boundAddr. Any matching packets are returned via the given buffer.
func (upc *BroadcastRawUDPConn) ReadFrom(b []byte) (int, net.Addr, error) {
	ipLen := IPv4MaximumHeaderSize
	udpLen := UDPMinimumSize

	for {
		pkt := make([]byte, ipLen+udpLen+len(b))
		n, _, err := upc.PacketConn.ReadFrom(pkt)
		if err != nil {
			return 0, nil, err
		}
		if n == 0 {
			return 0, nil, io.EOF
		}
		pkt = pkt[:n]
		buf := uio.NewBigEndianBuffer(pkt)

		// To read the header length, access data directly.
		ipHdr := IPv4(buf.Data())
		ipHdr = IPv4(buf.Consume(int(ipHdr.HeaderLength())))

		if ipHdr.TransportProtocol() != UDPProtocolNumber {
			continue
		}
		udpHdr := UDP(buf.Consume(udpLen))

		addr := &net.UDPAddr{
			IP:   net.IP(ipHdr.DestinationAddress()),
			Port: int(udpHdr.DestinationPort()),
		}
		if !udpMatch(addr, upc.boundAddr) {
			continue
		}
		srcAddr := &net.UDPAddr{
			IP:   net.IP(ipHdr.SourceAddress()),
			Port: int(udpHdr.SourcePort()),
		}
		return copy(b, buf.ReadAll()), srcAddr, nil
	}
}

// WriteTo implements net.PacketConn.WriteTo and broadcasts all packets at the
// raw socket level.
//
// WriteTo wraps the given packet in the appropriate UDP and IP header before
// sending it on the packet conn.
func (upc *BroadcastRawUDPConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, fmt.Errorf("must supply UDPAddr")
	}

	// Using the boundAddr is not quite right here, but it works.
	packet := udp4pkt(b, udpAddr, upc.boundAddr)

	// Broadcasting is not always right, but hell, what the ARP do I know.
	return upc.PacketConn.WriteTo(packet, &raw.Addr{HardwareAddr: BroadcastMac})
}
