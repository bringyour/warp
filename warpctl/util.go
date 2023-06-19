package main

import (
	"os/exec"
	"text/template"
	"bytes"
	"errors"
	"strings"
	"strconv"
	"fmt"
	"regexp"
)


func sudo(name string, args ...string) *exec.Cmd {
	flatArgs := []string{}
	flatArgs = append(flatArgs, name)
	flatArgs = append(flatArgs, args...)
	return exec.Command("sudo", flatArgs...)
}


func docker(name string, args ...string) *exec.Cmd {
	flatArgs := []string{}
	flatArgs = append(flatArgs, "docker")
	flatArgs = append(flatArgs, name)
	flatArgs = append(flatArgs, args...)
	return exec.Command("sudo", flatArgs...)
}


func templateString(text string, data ...map[string]any) string {
	t, err := template.New("").Parse(text)
	if err != nil {
		panic(err)
	}
	mergedData := map[string]any{}
	for _, d := range data {
		for key, value := range d {
			mergedData[key] = value
		}
	}
	out := &bytes.Buffer{}
	t.Execute(out, mergedData)
	return out.String()
}


func expandAnyPorts(portSpec any) ([]int, error) {
	switch v := portSpec.(type) {
	case int:
		return []int{v}, nil
	case string:
		return expandPorts(v)
	default:
		return nil, errors.New(fmt.Sprintf("Unknown ports type %T", v))
	}
}


func expandPorts(portsListStr string) ([]int, error) {
	portRangeRegex := regexp.MustCompile("^(\\d+)-(\\d+)$")
	portRegex := regexp.MustCompile("^(\\d+)$")
	ports := []int{}
	for _, portsStr := range strings.Split(portsListStr, ",") {
		if portStrs := portRangeRegex.FindStringSubmatch(portsStr); portStrs != nil {
			minPort, err := strconv.Atoi(portStrs[1])
			if err != nil {
				panic(err)
			}
			maxPort, err := strconv.Atoi(portStrs[2])
			if err != nil {
				panic(err)
			}
			for port := minPort; port <= maxPort; port += 1 {
				ports = append(ports, port)
			}
		} else if portStrs := portRegex.FindStringSubmatch(portsStr); portStrs != nil {
			port, err := strconv.Atoi(portStrs[1])
			if err != nil {
				panic(err)
			}
			ports = append(ports, port)
		} else {
			return nil, errors.New(fmt.Sprintf("Port must be either int min-max or int port (%s)", portsStr))
		}
	}
	return ports, nil
}


// func collapsePorts([]int ports) string {
// 	// FIXME
// }

