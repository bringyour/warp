package main

import (
	"os/exec"
	"text/template"
	"bytes"
	"errors"
	"strings"
	"strconv"
	"fmt"
	"sort"
	"regexp"
	"net"
	"runtime"
	"sync"
	"time"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/exp/slices"

	"github.com/coreos/go-semver/semver"
)



/*
type CommandList struct {
	commands []*exec.Cmd
	ignore map[int]bool
	Dir string
}

func NewCommandList() *CommandList {
	return &CommandList{
		commands: []*exec.Cmd{},
		ignore: map[int]bool{},
	}
}

func (self *CommandList) Sudo(name string, args ...string) *CommandList {
	cmd := sudo(name, args...)
	cmd.Dir = self.Dir
	self.commands = append(self.commands, cmd)
	return self
}

func (self *CommandList) Docker(name string, args ...string) *CommandList {
	cmd := docker(name, args...)
	cmd.Dir = self.Dir
	self.commands = append(self.commands, cmd)
	return self
}

func (self *CommandList) Add(cmd *exec.Cmd) *CommandList {
	self.commands = append(self.commands, cmd)
	return self
}

func (self *CommandList) IgnoreErrors() {
	self.ignore[len(self.commands) - 1] = true
}

func (self *CommandList) Run() {
	for i, cmd := range self.commands {
		fmt.Printf("RUNNING COMMAND %s\n", cmd)
		err := cmd.Run()
		if err != nil {
			if ignore, ok := self.ignore[i]; !ok || !ignore  {
				panic(err)
			}
		}
	}
}
*/



func runAndLog(cmd *exec.Cmd) error {
	err := cmd.Run()
	if err == nil {
		Err.Printf("%s (exited 0)\n", cmd)
	} else {
	    if exitError, ok := err.(*exec.ExitError); ok {
			Err.Printf("%s (exited %d)\n", cmd, exitError.ExitCode())
	    } else {
	    	Err.Printf("%s (error %s)\n", cmd, err)
	    }
	}
	return err
}


func sudo(name string, args ...string) *exec.Cmd {
	flatArgs := []string{}
	flatArgs = append(flatArgs, name)
	flatArgs = append(flatArgs, args...)
	return exec.Command("sudo", flatArgs...)
}


func docker(name string, args ...string) *exec.Cmd {
	flatArgs := []string{}
	flatArgs = append(flatArgs, name)
	flatArgs = append(flatArgs, args...)
	switch runtime.GOOS {
	case "linux":
		return sudo("docker", flatArgs...)
	default:
		return exec.Command("docker", flatArgs...)
	}
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


func collapsePorts(ports []int) string {
	parts := []string{}

	sort.Ints(ports)
	for i := 0; i < len(ports); {
		j := i + 1
		for j < len(ports) && ports[j] == ports[j - 1] + 1 {
			j += 1
		}
		if i == j - 1 {
			parts = append(parts, fmt.Sprintf("%d", ports[i]))
		} else {
			parts = append(parts, fmt.Sprintf("%d-%d", ports[i], ports[j - 1]))
		}
		i = j
	}

	return strings.Join(parts, ",")
}


func templateString(text string, data ...map[string]any) string {
	unindentedText := indentAndTrimString(text, 0)
	t, err := template.New("").Parse(unindentedText)
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


func indentAndTrimString(text string, indent int) string {
	// use the minimum indent of a contentful line

	contentfulLineRegex := regexp.MustCompile("^(\\s*)\\S")
	minIndent := -1

	lines := strings.Split(text, "\n")
	for _, line := range lines {
		if contentfulLineStrs := contentfulLineRegex.FindStringSubmatch(line); contentfulLineStrs != nil {
			lineIndent := len(contentfulLineStrs[1])
			if minIndent < 0 || lineIndent < minIndent{
				minIndent = lineIndent
			}
		}
	}

	if minIndent < 0 {
		minIndent = 0
	}

	indentStr := strings.Repeat(" ", indent)


	indentedLines := []string{}
	for i, line := range lines {
		if len(line) <= minIndent {
			// trim first and least empty lines
			if 0 < i && i < len(lines) - 1 {
				indentedLine := ""
				indentedLines = append(indentedLines, indentedLine)
			}
		} else {
			indentedLine := fmt.Sprintf("%s%s", indentStr, line[minIndent:])
			indentedLines = append(indentedLines, indentedLine)
		}
		
	}



	return strings.Join(indentedLines, "\n")
}



func nextIp(ipNet net.IPNet, count int) net.IP {
    ip := ipNet.IP.Mask(ipNet.Mask)
	ones, _ := ipNet.Mask.Size()
	i := ones / 8

	for k := 0; k < count; k += i {
		ip[i] += 0x01 >> (ones % 8)
		// propagate the overflow bit forward
		for j := i; ip[j] == 0 && j + 1 < len(ip); j += 1 {
			ip[j + 1] += 0x01
		}
	}

	return ip
}



func semverSortWithBuild(versions []*semver.Version) {
	slices.SortStableFunc(versions, func(a *semver.Version, b *semver.Version)(bool) {
		if a.LessThan(*b) {
			return true
		}
		if a.Equal(*b) {
			if a.Metadata < b.Metadata {
				return true
			}
		}
		return false
	})
}



func mapStr[KT comparable, VT any](m map[KT]VT) string {
	str := func(a any)(string) {
		switch v := a.(type) {
		case int:
			return strconv.Itoa(v)
		case string:
			return v
		default:
			return fmt.Sprintf("%s", v)
		}
	}
	pairStrs := []string{}
	for k, v := range m {
		pairStr := fmt.Sprintf("%s:%s", str(k), str(v))
		pairStrs = append(pairStrs, pairStr)
	}
	return fmt.Sprintf("{%s}", strings.Join(pairStrs, ", "))
}



type Event struct {
	mutex sync.Mutex
	value bool
	interrupt chan bool
}

func NewEvent() *Event {
	return &Event{
		interrupt: make(chan bool, 0),
	}
}

func (self *Event) Set() {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	self.value = true
	close(self.interrupt)
}

func (self *Event) IsSet() bool {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	return self.value
}

func (self *Event) WaitForSet(timeout time.Duration) bool {
	if !self.IsSet() {
		select {
		case <- self.interrupt:
		case <- time.After(timeout):
		}
	}
	return self.IsSet()
}

func (self *Event) SetOnSignals(signalValues ...syscall.Signal) func() {
	stopSignal := make(chan os.Signal, 2)
	for _, signalValue := range signalValues {
	    signal.Notify(stopSignal, signalValue)
	}
    go func() {
    	signalWatcher:
    	for {
	    	select {
			case sig, ok := <- stopSignal:
				if ok {
					Err.Printf("Stop signal detected (%d).\n", sig)
					self.Set()
				} else {
					break signalWatcher
				}
			}
		}
    }()
    return func(){
    	signal.Stop(stopSignal)
    	close(stopSignal)
    }
}



