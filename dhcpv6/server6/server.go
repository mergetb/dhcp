package server6

/*
  To use the DHCPv6 server code you have to call NewServer with two arguments:
  - an address to listen on, and
  - a handler function, that will be called every time a valid DHCPv6 packet is
    received.

  The address to listen on is used to know IP address, port and optionally the
  scope to create and UDP socket to listen on for DHCPv6 traffic.

  The handler is a function that takes as input a packet connection, that can be
  used to reply to the client; a peer address, that identifies the client sending
  the request, and the DHCPv6 packet itself. Just implement your custom logic in
  the handler.

  Optionally, NewServer can receive options that will modify the server object.
  Some options already exist, for example WithConn. If this option is passed with
  a valid connection, the listening address argument is ignored.

  Example program:


package main

import (
	"log"
	"net"

	"github.com/mergetb/dhcp/dhcpv6"
	"github.com/mergetb/dhcp/dhcpv6/server6"
)

func handler(conn net.PacketConn, peer net.Addr, m dhcpv6.DHCPv6) {
	// this function will just print the received DHCPv6 message, without replying
	log.Print(m.Summary())
}

func main() {
	laddr := net.UDPAddr{
		IP:   net.ParseIP("::1"),
		Port: 547,
	}
	server, err := server6.NewServer(&laddr, handler)
	if err != nil {
		log.Fatal(err)
	}

	// This never returns. If you want to do other stuff, dump it into a
	// goroutine.
	server.Serve()
}

*/

import (
	"log"
	"net"

	"github.com/mergetb/dhcp/dhcpv6"
	"golang.org/x/net/ipv6"
)

// Handler is a type that defines the handler function to be called every time a
// valid DHCPv6 message is received
type Handler func(conn net.PacketConn, peer net.Addr, m dhcpv6.DHCPv6)

// Server represents a DHCPv6 server object
type Server struct {
	conn    net.PacketConn
	handler Handler
}

// Serve starts the DHCPv6 server. The listener will run in background, and can
// be interrupted with `Server.Close`.
func (s *Server) Serve() error {
	log.Printf("Server listening on %s", s.conn.LocalAddr())
	log.Print("Ready to handle requests")

	defer s.Close()
	for {
		rbuf := make([]byte, 4096) // FIXME this is bad
		n, peer, err := s.conn.ReadFrom(rbuf)
		if err != nil {
			log.Printf("Error reading from packet conn: %v", err)
			return err
		}
		log.Printf("Handling request from %v", peer)

		d, err := dhcpv6.FromBytes(rbuf[:n])
		if err != nil {
			log.Printf("Error parsing DHCPv6 request: %v", err)
			continue
		}

		go s.handler(s.conn, peer, d)
	}
}

// Close sends a termination request to the server, and closes the UDP listener
func (s *Server) Close() error {
	return s.conn.Close()
}

// A ServerOpt configures a Server.
type ServerOpt func(s *Server)

// WithConn configures a server with the given connection.
func WithConn(conn net.PacketConn) ServerOpt {
	return func(s *Server) {
		s.conn = conn
	}
}

// NewServer initializes and returns a new Server object, listening on `addr`,
// and joining the multicast group ff02::1:2 . If `addr` is nil, IPv6 unspec is
// used. If `WithConn` is used with a non-nil address, `addr` and `ifname` have
// no effect. In such case, joining the multicast group is the caller's
// responsibility.
func NewServer(ifname string, addr *net.UDPAddr, handler Handler, opt ...ServerOpt) (*Server, error) {
	s := &Server{
		handler: handler,
	}

	for _, o := range opt {
		o(s)
	}

	if s.conn == nil {
		// no connection provided by the user, create a new one
		conn, err := net.ListenUDP("udp6", addr)
		if err != nil {
			return nil, err
		}
		// join multicast group on the specified interface
		var iface *net.Interface
		if ifname == "" {
			iface = nil
		} else {
			iface, err = net.InterfaceByName(ifname)
			if err != nil {
				return nil, err
			}
		}
		group := net.UDPAddr{
			IP:   dhcpv6.AllDHCPRelayAgentsAndServers,
			Port: dhcpv6.DefaultServerPort,
		}
		p := ipv6.NewPacketConn(conn)
		if err := p.JoinGroup(iface, &group); err != nil {
			return nil, err
		}
		s.conn = conn
	}
	return s, nil
}
