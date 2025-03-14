/*
Copyright © 2025 Aysuka Ansari, LLC
Copyrights apply to this source code.
Check LICENSE for details.
*/
package cmd

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"pragprog.com/rggo/cobra/pScan/scan"
)

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run a port scan on the hosts",
	RunE: func(cmd *cobra.Command, args []string) error {
		hostsFile, err := cmd.Flags().GetString("hosts-file")
		if err != nil {
			return err
		}

		portsString, err := cmd.Flags().GetString("ports")
		if err != nil {
			return err
		}

		ports, err := getPortsSlice(portsString)
		if err != nil {
			return err
		}

		return scanAction(os.Stdout, hostsFile, ports)
	},
}

func getPortsSlice(ps string) ([]int, error) {
	var ports []int

	if strings.Contains(ps, ",") {

		stringSlice := strings.Split(ps, ",")

		for _, v := range stringSlice {
			port, err := strconv.Atoi(v)
			if err != nil {
				return nil, err
			}

			if port < 1 || port > 65535 {
				return nil, fmt.Errorf("invalid port value: %d (port should be between 1 - 65535)", port)
			}
			ports = append(ports, port)
		}
	} else if strings.Contains(ps, "-") {

		stringSlice := strings.Split(ps, "-")
		if len(stringSlice) != 2 {
			return nil, fmt.Errorf("invalid port value. Make sure that port value lies between 1 - 65535")
		}

		lower, err := strconv.Atoi(stringSlice[0])
		if err != nil {
			return nil, err
		}

		upper, err := strconv.Atoi(stringSlice[1])
		if err != nil {
			return nil, err
		}

		if lower < 1 || lower > 65535 {
			return nil, fmt.Errorf("invalid port value: %d (port should be between 1 - 65535)", lower)
		}
		if upper < 1 || upper > 65535 {
			return nil, fmt.Errorf("invalid port value: %d (port should be between 1 - 65535)", upper)
		}
		if lower > upper {
			return nil, fmt.Errorf("invalid port range: %d-%d (port should be between 1 - 65535)", lower, upper)
		}

		for i := lower; i <= upper; i++ {
			ports = append(ports, i)
		}
	} else {

		port, err := strconv.Atoi(ps)
		if err != nil {
			return nil, err
		}
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid port value: %d (port should be between 1 - 65535)", port)
		}
		ports = append(ports, port)
	}

	return ports, nil
}

func scanAction(out io.Writer, hostsFile string, ports []int) error {
	hl := &scan.HostsList{}

	if err := hl.Load(hostsFile); err != nil {
		return err
	}

	results := scan.Run(hl, ports)

	return printResults(out, results)
}

func printResults(out io.Writer, results []scan.Results) error {
	message := ""

	for _, r := range results {
		message += fmt.Sprintf("%s:", r.Host)

		if r.NotFound {
			message += " Host not found\n\n"
			continue
		}

		message += fmt.Sprintln()

		for _, p := range r.PortStates {
			message += fmt.Sprintf("\t%d: %s\n", p.Port, p.Open)
		}

		message += fmt.Sprintln()
	}

	_, err := fmt.Fprint(out, message)

	return err
}

func init() {
	rootCmd.AddCommand(scanCmd)

	scanCmd.Flags().StringP("ports", "p", "22,80,443", "ports to scan")
	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// scanCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// scanCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
