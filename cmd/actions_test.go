package cmd

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"pragprog.com/rggo/cobra/pScan/scan"
)

func setup(t *testing.T, hosts []string, initList bool) (string, func()) {
	// Create temp file
	tf, err := os.CreateTemp("", "pScan")
	if err != nil {
		t.Fatal(err)
	}
	tf.Close()

	// Initialize list if needed
	if initList {
		hl := &scan.HostsList{}

		for _, h := range hosts {
			hl.Add(h)
		}

		if err := hl.Save(tf.Name()); err != nil {
			t.Fatal(err)
		}
	}

	// Return temp file name and cleanup function
	return tf.Name(), func() {
		os.Remove(tf.Name())
	}
}

func TestHostActions(t *testing.T) {
	// Define hosts for actions test
	hosts := []string{
		"host1",
		"host2",
		"host3",
	}

	// Test cases for Action test
	testCases := []struct {
		name           string
		args           []string
		expectedOut    string
		initList       bool
		actionFunction func(io.Writer, string, []string) error
	}{
		{
			name:           "AddAction",
			args:           hosts,
			expectedOut:    "Added host: host1\nAdded host: host2\nAdded host: host3\n",
			initList:       false,
			actionFunction: addAction,
		},
		{
			name:           "ListAction",
			expectedOut:    "host1\nhost2\nhost3\n",
			initList:       true,
			actionFunction: listAction,
		},
		{
			name:           "DeleteAction",
			args:           []string{"host1", "host2"},
			expectedOut:    "Deleted host: host1\nDeleted host: host2\n",
			initList:       true,
			actionFunction: deleteAction,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup Action test
			tf, cleanup := setup(t, hosts, tc.initList)
			defer cleanup()

			// Define var to capture Action output
			var out bytes.Buffer

			// Execute Action and capture output
			if err := tc.actionFunction(&out, tf, tc.args); err != nil {
				t.Fatalf("Expected no error, got %q\n", err)
			}

			// Test Actions output
			if out.String() != tc.expectedOut {
				t.Errorf("Expected output %q, got %q\n", tc.expectedOut, out.String())
			}
		})
	}
}

func TestIntegration(t *testing.T) {
	// Define hosts for integration test
	hosts := []string{
		"host1",
		"host2",
		"host3",
	}

	// Setup integration test
	tf, cleanup := setup(t, hosts, false)
	defer cleanup()

	delHost := "host2"

	hostsEnd := []string{
		"host1",
		"host3",
	}

	// Define var to capture output
	var out bytes.Buffer

	// Define expected output for all actions
	expectedOut := ""
	for _, v := range hosts {
		expectedOut += fmt.Sprintf("Added host: %s\n", v)
	}

	expectedOut += strings.Join(hosts, "\n")
	expectedOut += fmt.Sprintln()
	expectedOut += fmt.Sprintf("Deleted host: %s\n", delHost)
	expectedOut += strings.Join(hostsEnd, "\n")
	expectedOut += fmt.Sprintln()
	expectedOut += fmt.Sprintln("=== tcp port scanning result ===")
	expectedOut += fmt.Sprintln()
	for _, v := range hostsEnd {
		expectedOut += fmt.Sprintf("%s: Host not found\n", v)
		expectedOut += fmt.Sprintln()
	}

	// Add hosts to the list
	if err := addAction(&out, tf, hosts); err != nil {
		t.Fatalf("Expected no error, got %q\n", err)
	}

	// List hosts
	if err := listAction(&out, tf, nil); err != nil {
		t.Fatalf("Expected no error, got %q\n", err)
	}

	// Delete host2
	if err := deleteAction(&out, tf, []string{delHost}); err != nil {
		t.Fatalf("Expected no error, got %q\n", err)
	}

	// List hosts after delete
	if err := listAction(&out, tf, nil); err != nil {
		t.Fatalf("Expected no error, got %q\n", err)
	}

	// Scan hosts
	if err := scanAction(&out, tf, nil, "tcp", "none", 1000); err != nil {
		t.Fatalf("Expected no error, got %q\n", err)
	}

	// Test integration output
	if out.String() != expectedOut {
		t.Errorf("Expected output %q, got %q\n", expectedOut, out.String())
	}
}

func TestScanAction(t *testing.T) {
	// Define hosts for scan test
	hosts := []string{
		"localhost",
		"unknownhostoutthere",
	}

	// Setup scan test
	tf, cleanup := setup(t, hosts, true)
	defer cleanup()

	ports := []int{}

	// Init ports, 1 open, 1 closed
	for i := 0; i < 2; i++ {
		ln, err := net.Listen("tcp", net.JoinHostPort("localhost", "0"))
		if err != nil {
			t.Fatal(err)
		}

		defer ln.Close()

		_, portStr, err := net.SplitHostPort(ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}

		port, err := strconv.Atoi(portStr)
		if err != nil {
			t.Fatal(err)
		}

		ports = append(ports, port)

		if i == 1 {
			ln.Close()
		}
	}

	// Define expected output for scan action
	expectedOut := fmt.Sprintln("=== tcp port scanning result ===")
	expectedOut += fmt.Sprintln()
	expectedOut += fmt.Sprintln("localhost:")
	expectedOut += fmt.Sprintf("\t%d: open\n", ports[0])
	expectedOut += fmt.Sprintln()
	expectedOut += fmt.Sprintln("unknownhostoutthere: Host not found")
	expectedOut += fmt.Sprintln()

	// Define var to capture scan output
	var out bytes.Buffer

	// Execute scan and capture output
	if err := scanAction(&out, tf, ports, "tcp", "open", 1000); err != nil {
		t.Fatalf("Expected no error, got %q\n", err)
	}

	// Test scan output
	if out.String() != expectedOut {
		t.Errorf("Expected output %q, got %q\n", expectedOut, out.String())
	}
}

func TestGetPortsSliceSuccess(t *testing.T) {
	testCases := []struct {
		name        string
		portString  string
		expectedRes []int
	}{
		{
			"Single", "80", []int{80},
		},
		{
			"Range", "1-5", []int{1, 2, 3, 4, 5},
		},
		{
			"Specified", "4,5,80,8080", []int{4, 5, 80, 8080},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// check if error occured
			res, err := getPortsSlice(tc.portString)
			if err != nil {
				t.Errorf("Expected no error, but got %q\n", err)
			}

			// compare result slice
			if !slices.Equal(res, tc.expectedRes) {
				t.Errorf("Expected %q, but got %q", res, tc.expectedRes)
			}
		})
	}
}

func TestGetPortsSliceFailed(t *testing.T) {
	testCases := []struct {
		name        string
		portString  string
		expectedRes []int
	}{
		{
			"SingleNegative", "-2", nil,
		},
		{
			"SingleTooBig", "999999", nil,
		},
		{
			"SingleNonNumeric", "a", nil,
		},
		{
			"Range", "2000-5", nil,
		},
		{
			"Specified", "1,a,80,8080", nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := getPortsSlice(tc.portString)
			if err == nil {
				t.Error("Expected error, but got nil")
			}

			if res != nil {
				t.Errorf("Expected res to be nil, but got %q", res)
			}
		})
	}
}
