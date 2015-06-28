package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
)

// Need worker pool because running 1 goroutine per port exhausts file descriptors
const MAX_WORKERS = 100

type PortRange struct {
	Start uint64
	End   uint64
}

func (pr *PortRange) String() string {
	return fmt.Sprintf("[%v,%v)", pr.Start, pr.End)
}

// Run the port scanner
func main() {
	var host, port_range_arg string
	var debug bool
	flag.StringVar(&host, "c", "", "host to scan")
	flag.StringVar(&port_range_arg, "r", "", "ports to scan")
	flag.BoolVar(&debug, "debug", false, "include results on all ports")
	flag.Parse()

	if host == "" || port_range_arg == "" {
		fmt.Println("Usage: portscan -c <host> -range port|start-end, [port|start-end ...] [-debug]")
		os.Exit(1)
	}
	prs, err := parseRanges(port_range_arg)
	if err != nil {
		log.Fatal(err)
	}

	// Format results
	for _, pr := range prs {
		results := ScanPorts(host, pr)
		for port, success := range results {
			if success || debug {
				fmt.Printf("%v: %v\n", port, success)
			}
		}
	}
}

// Parse port ranges spec
func parseRanges(ranges_str string) ([]*PortRange, error) {
	parts := strings.Split(ranges_str, ",")
	ranges := make([]*PortRange, 0)
	for _, part := range parts {
		rg, err := parseRange(part)
		if err != nil {
			return nil, err
		}
		ranges = append(ranges, rg)
	}
	return ranges, nil
}

//TODO: check overflow
func parseRange(range_str string) (*PortRange, error) {
	parts := strings.SplitN(range_str, "-", 2)
	nums := make([]uint64, len(parts))
	for i, v := range parts {
		n, err := strconv.ParseUint(v, 10, 16)
		if err != nil {
			return nil, err
		}
		nums[i] = n
	}
	switch len(nums) {
	case 1:
		return &PortRange{
			Start: nums[0],
			End:   nums[0] + 1,
		}, nil
	case 2:
		return &PortRange{
			Start: nums[0],
			End:   nums[1],
		}, nil
	default:
		return nil, fmt.Errorf("Invalid Port Specification")
	}
}

// Container for scan results from workers
type ScanResult struct {
	Port    uint64
	Success bool
	Err     error
}

// Run the scan with a worker pool; memory usage grows in proportion
// with number of ports scanned to prevent deadlock from blocking channels
func ScanPorts(host string, pr *PortRange) map[uint64]bool {
	num_ports := pr.End - pr.Start + 1
	results := make(map[uint64]bool)
	jobpipe := make(chan uint64, num_ports)
	respipe := make(chan *ScanResult, num_ports)

	// Start workers
	for worker := 0; worker < MAX_WORKERS; worker++ {
		go scanWorker(host, jobpipe, respipe)
	}

	// Seed w/ jobs
	for port := pr.Start; port < pr.End+1; port++ {
		jobpipe <- port
	}

	// Receive results
	received := uint64(0)
	for received < pr.End-pr.Start {
		res := <-respipe
		results[res.Port] = res.Success
		received += 1
	}
	return results
}

// Worker function; pull from job queue forever and return results on result
// queue
func scanWorker(host string, jobpipe chan uint64, respipe chan *ScanResult) {
	for job := <-jobpipe; ; job = <-jobpipe {
		respipe <- scanPort(host, job)
	}
}

// Simple scan of a single port
//	- Just tries to connect to <host>:<port> over TCP and checks for error
func scanPort(host string, port uint64) *ScanResult {
	conn, err := net.Dial("tcp", fmt.Sprintf("%v:%v", host, port))
	result := ScanResult{
		Port:    port,
		Success: err == nil,
		Err:     err,
	}
	if conn != nil {
		conn.Close()
	}
	return &result
}
