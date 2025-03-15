package scan

import (
	"fmt"
	"net"
	"time"
)

// PortState represents the state of a single TCP port
type PortState struct {
	Port int
	Open state
}

type state bool

// String converts the boolean value of state to a human readable string
func (s state) String() string {
	if s {
		return "open"
	}
	return "closed"
}

// scanPort performs a port scan on a single TCP port
func scanPort(host string, port int, network string, timeout int) PortState {

	p := PortState{
		Port: port,
		Open: false,
	}

	address := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	if network == "tcp" {
		scanConn, err := net.DialTimeout(network, address, time.Duration(timeout)*time.Millisecond)

		if err != nil {
			return p
		}

		scanConn.Close()
		p.Open = true
	} else if network == "udp" {
		udpAddr, err := net.ResolveUDPAddr(network, address)
		if err != nil {
			return p
		}

		udpConn, err := net.DialUDP(network, nil, udpAddr)
		if err != nil {
			return p
		}

		payload := []byte("Hello")

		_, err = udpConn.Write(payload)
		if err != nil {
			return p
		}

		res := make([]byte, 64)

		udpConn.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Millisecond))

		n, err := udpConn.Read(res)
		if err != nil {
			return p
		}

		if n > 0 {
			p.Open = true
		}

		udpConn.Close()
	}

	return p
}

// Results represents the scan results for a single host
type Results struct {
	Host       string
	NotFound   bool
	PortStates []PortState
}

// Run performs a port scan on the hosts list
func Run(hl *HostsList, ports []int, network string, timeout int) []Results {
	res := make([]Results, 0, len(hl.Hosts))

	for _, h := range hl.Hosts {
		r := Results{
			Host: h,
		}

		if _, err := net.LookupHost(h); err != nil {
			r.NotFound = true
			res = append(res, r)
			continue
		}

		// TODO: Implement go concurrency for parallel scanning
		for _, p := range ports {
			r.PortStates = append(r.PortStates, scanPort(h, p, network, timeout))
		}

		res = append(res, r)
	}

	return res
}
