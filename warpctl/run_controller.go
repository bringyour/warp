package main


import (
	"os"
	"os/exec"
	"time"
	"strings"
	"fmt"
	"strconv"
	"errors"
	"path"
	"net"
	"net/http"
	"io"
	"encoding/json"
	"regexp"


	"github.com/coreos/go-semver/semver"
	"github.com/apparentlymart/go-cidr/cidr"
)


// Create docker networks as follows:
// FOR NON-SERVICE NETWORKS DISABLE MASQ
// docker network create --attachable --opt 'com.docker.network.bridge.name=warp1' --opt 'com.docker.network.bridge.enable_ip_masquerade=false' warp1 
// docker network create --attachable --opt 'com.docker.network.bridge.name=warpsservices' warpsservices



const (
	MOUNT_MODE_NO = "no"
	MOUNT_MODE_YES = "yes"
	MOUNT_MODE_ROOT = "root"
)


type RunWorker struct {
	env string
	service string
	block string
	portBlocks *PortBlocks
	servicesDockerNetwork *DockerNetwork
	routingTable *RoutingTable
	dockerNetwork *DockerNetwork

	vaultMountMode string
	keysMountMode string

	deployedVersion *semver.Version
	deployedKeysVersion *semver.Version

	// fixme vault bind mode
	// fixme keys bind mode
	quit chan os.Signal
}


func (self *RunWorker) run() {
	// on start, deploy the latest version and start the watcher loop

	// enable policy routing
	if self.routingTable != nil {
		self.initRoutingTable()
	}

	self.initBlockRedirect()

	self.deployedVersion = nil
	self.deployedKeysVersion = nil

	// watch for new versions until killed
	watcher:
	for {
		latestVersion, latestKeysVersion := self.getLatestVersion()
		if self.deployedVersion != latestVersion || 
				self.keysMountMode == MOUNT_MODE_YES && self.deployedKeysVersion != latestKeysVersion {
			// deploy new version
			self.deployedVersion = latestVersion
			self.deployedKeysVersion = latestKeysVersion

			if self.deployedVersion == nil {
				announceRunWaitForVersion()
			} else if self.deployedKeysVersion == nil && self.keysMountMode == MOUNT_MODE_YES {
				announceRunWaitForKeys()
			} else {
				func() {
					announceRunStart()
					defer func() {
						if err := recover(); err != nil {
							announceRunError()	
						}
					}()
					err := self.deploy()
					if err != nil {
						announceRunFail()
					} else {
						announceRunSuccess()
					}
				}()
			}
		}
		select {
		case <- self.quit:
			break watcher
		case <-time.After(5 * time.Second):
			// continue
		}
	}
}


// service version, keys version
func (self *RunWorker) getLatestVersion() (*semver.Version, *semver.Version) {

	state := getWarpState()

	versionMeta := getVersionMeta(self.env, self.service)
	latestVersion := versionMeta.latestBlocks[self.block]

	var latestKeysVersion *semver.Version
	if state.warpSettings.KeysHome == nil {
		latestKeysVersion = nil
	} else {
		entries, err := os.ReadDir(*state.warpSettings.KeysHome)
	    if err != nil {
	    	panic(err)
	    }

	    keysVersions := []*semver.Version{}
	    for _, entry := range entries {
	    	if entry.IsDir() {
	    		if version, err := semver.NewVersion(entry.Name()); err == nil {
	    			keysVersions = append(keysVersions, version)
	    		}
	    	}
	    }
	    semver.Sort(keysVersions)

	    
	    if len(keysVersions) == 0 {
	    	latestKeysVersion = nil
	    } else {
	    	latestKeysVersion = keysVersions[len(keysVersions) - 1]
	    }
	}

    return latestVersion, latestKeysVersion
}



// docker kill --signal="<signal>"




func (self *RunWorker) initRoutingTable() {
	cmds := []*exec.Cmd{
		sudo("ip", "route", "flush",
			 "table", self.routingTable.tableName),

		// add routes for:
		// - interface (default)
		// - docker services interface
		// - docker interface

		sudo("ip", "route", "add", self.routingTable.interfaceIpv4Subnet, 
			 "dev", self.routingTable.interfaceName, 
			 "src", self.routingTable.interfaceIpv4, 
			 "table", self.routingTable.tableName),
	    sudo("ip", "route", "add", self.servicesDockerNetwork.interfaceIpv4Subnet, 
	    	 "dev", self.servicesDockerNetwork.interfaceName,
	    	 "src", self.servicesDockerNetwork.interfaceIpv4,
	    	 "table", self.routingTable.tableName),
	   	sudo("ip", "route", "add", self.dockerNetwork.interfaceIpv4Subnet, 
	    	 "dev", self.dockerNetwork.interfaceName,
	    	 "src", self.dockerNetwork.interfaceIpv4,
	    	 "table", self.routingTable.tableName),
	   	sudo("ip", "route", "add", "default",
	   		 "via", self.routingTable.interfaceIpv4Gateway,
	   		 "dev", self.routingTable.interfaceName,
	   		 "table", self.routingTable.tableName),

	    // use the table from:
	    // - interface ip (sockets bound to the interface)
	    // - docker interface subnet (sockets in docker containers in the network)

	   	sudo("ip", "rule", "add",
	   		 "from", self.routingTable.interfaceIpv4Gateway,
	   		 "table", self.routingTable.tableName),
		sudo("ip", "rule", "add",
	   		 "from", self.dockerNetwork.interfaceIpv4Subnet,
	   		 "table", self.routingTable.tableName),
	}

	for _, cmd := range cmds {
		err := cmd.Run()
		if err != nil {
			panic(err)
		}
	}
}



func (self *RunWorker) iptablesChainName() string {
	return fmt.Sprintf(
		"WARP-%s-%s-%s",
		strings.ToUpper(self.env),
		strings.ToUpper(self.service),
		strings.ToUpper(self.block),
	)
}


func (self *RunWorker) initBlockRedirect() {
	chainName := self.iptablesChainName()
	cmds := []*exec.Cmd{
		sudo("iptables", "-t", "nat", "-N", chainName),

		// apply chain to external traffic to local
		sudo("iptables", "-t", "nat", "-I", "PREROUTING",
			 "-m", "addrtype", "--dst-type", "LOCAL",
			 "-j", chainName),

		// apply chain to local traffic to local
		sudo("iptables", "-t", "nat", "-I", "OUTPUT",
			 "-m", "addrtype", "--dst-type", "LOCAL",
			 "-j", chainName),
	}

	for _, cmd := range cmds {
		err := cmd.Run()
		if err != nil {
			panic(err)
		}
	}
}



func (self *RunWorker) deploy() error {
	externalsPortsToInternalPort, dockerInternalPortsToInternalPort := self.findDeployPorts()

    deployedContainerId, err := self.startContainer(dockerInternalPortsToInternalPort)
    if err != nil {
    	return err
    }
    success := false
    defer func() {
		if !success {
	    	go newKillWorker(deployedContainerId).run()
	    }
    }()

	if err := self.pollContainerStatus(dockerInternalPortsToInternalPort, 300 * time.Second); err != nil {
		return err
	}

	runningContainers, err := self.findRunningContainers()
	if err != nil {
		return err
	}
	// verify the internal ports
	for _, internalPort := range dockerInternalPortsToInternalPort {
		if containerId, ok := runningContainers[internalPort]; !ok || deployedContainerId != containerId {
			return errors.New(fmt.Sprintf("Container is not listening on internal port %d", internalPort))
		}
	}

    containerIds := map[string]bool{}
    for _, containerId := range runningContainers {
    	containerIds[containerId] = true
    }
    for containerId, _ := range containerIds {
    	if containerId != deployedContainerId {
		    go newKillWorker(containerId).run()
		}
	}

    self.redirect(externalsPortsToInternalPort)
    success = true
    return nil
}

func (self *RunWorker) findDeployPorts() (map[int]int, map[int]int) {
	for {
		externalsPortsToInternalPort := map[int]int{}

		runningContainers, err := self.findRunningContainers()
		if err != nil {
			for externalPort, internalPorts := range self.portBlocks.externalsToInternals {
				for _, internalPort := range internalPorts {
					if _, ok := runningContainers[internalPort]; !ok {
						externalsPortsToInternalPort[externalPort] = internalPort
						break
					}
				}
			}
		}

		if len(externalsPortsToInternalPort) < len(self.portBlocks.externalsToInternals) {
			select {
			case <- self.quit:
				panic("Could not allocate ports.")
			case <-time.After(5 * time.Second):
				// continue
			}
		}

		dockerInternalPortsToInternalPort := map[int]int{}
		for externalPort, dockerInternalPort := range self.portBlocks.externalsToDockerInternal {
			internalPort := externalsPortsToInternalPort[externalPort]
			dockerInternalPortsToInternalPort[dockerInternalPort] = internalPort
		}

		return externalsPortsToInternalPort, dockerInternalPortsToInternalPort
	}
}

func (self *RunWorker) startContainer(dockerInternalPortsToInternalPort map[int]int) (string, error) {
	state := getWarpState()

	vaultMount := "/srv/warp/vault"
	keysMount := "/srv/warp/keys"
	localMount := "/srv/warp/keys"

	containerName := fmt.Sprintf(
		"%s-%s-%s-%s-%d",
		self.env,
		self.service,
		self.block,
		self.deployedVersion.String(),
		time.Now().UnixMilli(),
	)
	imageName := fmt.Sprintf(
		"%s/%s-%s:%s",
		state.warpSettings.DockerNamespace,
		self.env,
		self.service,
		self.deployedVersion.String(),
	)

	args := []string{}
	args = append(args, []string{
		"--name", containerName,
		"-d",
		"--restart=on-failure",
	}...)
	for dockerInternalPort, internalPort := range dockerInternalPortsToInternalPort {
		args = append(args, []string{"-p", fmt.Sprintf("%d:%d", internalPort, dockerInternalPort)}...)
	}
	if self.dockerNetwork != nil {
		args = append(args, []string{"--network", self.dockerNetwork.networkName}...)
	} else {
		args = append(args, []string{"--network", self.servicesDockerNetwork.networkName}...)
	}
	if self.dockerNetwork != nil {
		args = append(args, []string{"--add-host", fmt.Sprintf("%s:%s", self.dockerNetwork.networkName, self.dockerNetwork.interfaceIpv4Gateway)}...)
	}
	args = append(args, []string{"--add-host", fmt.Sprintf("%s:%s", self.servicesDockerNetwork.networkName, self.servicesDockerNetwork.interfaceIpv4Gateway)}...)

	switch self.vaultMountMode {
	case MOUNT_MODE_YES:
		if state.warpSettings.VaultHome == nil {
			return "", errors.New("Missing warp vault home")
		}
		args = append(args, []string{
			"--mount",
			fmt.Sprintf("type=bind,source=%s,target=%s,readonly", *state.warpSettings.VaultHome, vaultMount),
		}...)
	}

	switch self.keysMountMode {
	case MOUNT_MODE_YES:
		if state.warpSettings.KeysHome == nil {
			return "", errors.New("Missing warp keys home")
		}
		keysVersionHome := path.Join(*state.warpSettings.KeysHome, self.deployedKeysVersion.String())
		args = append(args, []string{
			"--mount",
			fmt.Sprintf("type=bind,source=%s,target=%s,readonly", keysVersionHome, keysMount),
		}...)
	case MOUNT_MODE_ROOT:
		if state.warpSettings.KeysHome == nil {
			return "", errors.New("Missing warp keys home")
		}
		// mount as read-write (default)
		args = append(args, []string{
			"--mount",
			fmt.Sprintf("type=bind,source=%s,target=%s", *state.warpSettings.KeysHome, keysMount),
		}...)
	}

	args = append(args, imageName)

	cmd := docker("run", args...)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	// `docker run` prints the container_id as the only output
	container_id := string(out)
	return container_id, nil
}

func (self *RunWorker) pollContainerStatus(dockerInternalPortsToInternalPort map[int]int, timeout time.Duration) error {
	httpPort, ok := dockerInternalPortsToInternalPort[80]
	if !ok {
		// no http port - assume ok
		return nil
	}

	client := &http.Client{}

	poll := func()(error) {
		statusRequest, err := http.NewRequest(
			"GET",
			fmt.Sprintf("http://127.0.0.1:%d", httpPort),
			nil,
		)
		if err != nil {
			return err
		}
		statusRequest.Header.Add("Host", fmt.Sprintf("%s-%s", self.env, self.service))
		statusResponse, err := client.Do(statusRequest)
		if err != nil {
			return err
		}
		var warpStatusResponse WarpStatusResponse
		body, err := io.ReadAll(statusResponse.Body)
	    if err != nil {
	    	return err
	    }
		err = json.Unmarshal(body, &warpStatusResponse)
		if err != nil {
			return err
		}
		if warpStatusResponse.IsError() {
			return errors.New(warpStatusResponse.Status)
		}
		return nil
	}

	endTime := time.Now().Add(timeout)
	for {
		err := poll()
		if err == nil {
			return nil
		}
		select {
		case <- self.quit:
			return errors.New("quit")
		case <-time.After(5 * time.Second):
			// continue
		}
		if time.Now().After(endTime) {
			return err
		}
	}
}

func (self *RunWorker) redirect(externalsPortsToInternalPort map[int]int) {
	chainName := self.iptablesChainName()
    // remove the rule then insert it back at the end
    for _, op := range []string{"-D", "-A"} {
    	for externalPort, internalPort := range externalsPortsToInternalPort {
		    cmd := sudo("iptables", "-t", "nat", op, chainName,
		    	        "-p", "tcp", "-m", "tcp", "--dport", strconv.Itoa(externalPort),
		    	        "-j", "REDIRECT", "--to-ports", strconv.Itoa(internalPort))
		    err := cmd.Run()
		    if err != nil {
		    	panic(err)
		    }
		}
	}
	// for efficiency, remove other rules at the front of the chain
	// FIXME
	// "iptables -L chainName --line-numbers"
	// "iptables -t nat -D chainName 1"
}




/*
type ContainerList = []Container

Container
Id string
HostConfig *HostConfig

HostConfig
PortBindings map[string][]*PortBinding

PortBinding
HostIp string
HostPort string
*/


type ContainerList = []*Container

type Container struct {
	ContainerId string `json:"Id"`
	HostConfig *HostConfig `json:"HostConfig"`
}

type HostConfig struct {
	PortBindings map[string][]*PortBinding `json:"PortBindings"`
}

type PortBinding struct {
	HostIp string `json:"HostIp"`
	HostPort string `json:"HostPort"`
}


// map internal port to running container_id for all running containers
func (self *RunWorker) findRunningContainers() (map[int]string, error) {
	psCommand := docker("ps", "--format", "{{.ID}}")
	out, err := psCommand.Output()
	if err != nil {
		return nil, err
	}
	containerIds := strings.Split(string(out), "\n")
	inspectCommand := docker("inspect", containerIds...)
	out, err = inspectCommand.Output()
	if err != nil {
		return nil, err
	}

	var containerList ContainerList
	err = json.Unmarshal(out, &containerList)
	if err != nil {
		return nil, err
	}

	runningContainers := map[int]string{}

	for _, container := range containerList {
		for _, portBindings := range container.HostConfig.PortBindings {
			for _, portBinding := range portBindings {
				internalPort, err := strconv.Atoi(portBinding.HostPort)
				if err != nil {
					return nil, err
				}
				runningContainers[internalPort] = container.ContainerId
			}
		}
	}

	return runningContainers, nil
}




type PortBlocks struct {
	externalsToInternals map[int][]int
	externalsToDockerInternal map[int]int
}


// external:dockerInternal:p-P,p;external:dockerInternal:...
func parsePortBlocks(portBlocksStr string) *PortBlocks {
	externalsToInternals := map[int][]int{}
	externalsToDockerInternal := map[int]int{}

	externalStrs := strings.Split(portBlocksStr, ";")
	portRangeRegex := regexp.MustCompile("^(\\d+)-(\\d+)$")
	portRegex := regexp.MustCompile("^(\\d+)$")
	for _, externalStr := range externalStrs {
		externalStrSplit := strings.SplitN(externalStr, ":", 3)
		externalPort, err := strconv.Atoi(externalStrSplit[0])
		if err != nil {
			panic(fmt.Sprintf("Port block must be int externalport:dockerport:portlist (%s)", externalStrSplit[0]))
		}
		dockerInternalPort, err := strconv.Atoi(externalStrSplit[1])
		if err != nil {
			panic(fmt.Sprintf("Port block must be int externalport:dockerport:portlist (%s)", externalStrSplit[0]))
		}
		internalPorts := []int{}
		for _, portsStr := range strings.Split(externalStrSplit[2], ",") {
			if portStrs := portRangeRegex.FindStringSubmatch(portsStr); portStrs != nil {
				minPort, err := strconv.Atoi(portStrs[0])
				if err != nil {
					panic(err)
				}
				maxPort, err := strconv.Atoi(portStrs[1])
				if err != nil {
					panic(err)
				}
				for port := minPort; port <= maxPort; port += 1 {
					internalPorts = append(internalPorts, port)
				}
			} else if portStrs := portRegex.FindStringSubmatch(portsStr); portStrs != nil {
				port, err := strconv.Atoi(portStrs[0])
				if err != nil {
					panic(err)
				}
				internalPorts = append(internalPorts, port)
			} else {
				panic(fmt.Sprintf("Port must be either int min-max or port (%s)", portsStr))
			}
		}
		externalsToInternals[externalPort] = internalPorts
		externalsToDockerInternal[externalPort] = dockerInternalPort
	}
	return &PortBlocks{
		externalsToInternals: externalsToInternals,
		externalsToDockerInternal: externalsToDockerInternal,
	}
}


type NetworkInterface struct {
	interfaceName string
	interfaceIpv4 string
	interfaceIpv4Subnet string
	interfaceIpv4Gateway string
}


type DockerNetwork struct {
	networkName string
	NetworkInterface
}


func parseDockerNetwork(dockerNetworkStr string) *DockerNetwork {
	// assume the network name is the interface name
	interfaceName := dockerNetworkStr

	networkInterfaces, err := getNetworkInterfaces(interfaceName)
	if err != nil {
		panic(err)
	}
	if len(networkInterfaces) == 0 {
		panic(errors.New(fmt.Sprintf("Could not map docker interface %s to interface", interfaceName)))
	}
	if 0 < len(networkInterfaces) {
		panic(errors.New(fmt.Sprintf("More than one network attached to interface %s", interfaceName)))
	}
	networkInterface := networkInterfaces[0]

	return &DockerNetwork{
		networkName: dockerNetworkStr,
		NetworkInterface: *networkInterface,
	}
}

/*
DockerNetworks = []DockerNetwork

DockerNetwork
Name string
IPAM *DockerNetworkIpam

DockerNetworkIpam
Config []*DockerNetworkIpConfig

DockerNetworkIpConfig
Subnet
Gateway

*/


type RoutingTable struct {
	interfaceName string
	tableName string
	NetworkInterface
}

// interface:rt_table_name
// inspect the local interface for the ip address
func parseRoutingTable(routingTableStr string) *RoutingTable {
	routingTableStrSplit := strings.SplitN(routingTableStr, ":", 2)
	interfaceName := routingTableStrSplit[0]
	tableName := routingTableStrSplit[1]


	// ifconfig
	// see https://github.com/golang/go/issues/12551

	networkInterfaces, err := getNetworkInterfaces(interfaceName)
	if err != nil {
		panic(err)
	}
	if len(networkInterfaces) == 0 {
		panic(errors.New(fmt.Sprintf("Could not find interface %s", interfaceName)))
	}
	if 0 < len(networkInterfaces) {
		panic(errors.New(fmt.Sprintf("More than one network attached to interface %s", interfaceName)))
	}
	networkInterface := networkInterfaces[0]


	return &RoutingTable{
		interfaceName: interfaceName,
		tableName: tableName,
		NetworkInterface: *networkInterface,
	}
}


func getNetworkInterfaces(interfaceName string) ([]*NetworkInterface, error) {
	// see https://github.com/golang/go/issues/12551

	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, err
	}

    addrs, err := iface.Addrs()
    if err != nil {
        return nil, err
    }

    networkInterfaces := []*NetworkInterface{}

    for _, addr := range addrs {
        if netw, ok := addr.(*net.IPNet); ok {
            if netw.IP.To4() != nil {
            	gatewayIp, err := cidr.Host(netw, 1)
            	if err != nil {
            		return nil, err
            	}

            	networkInterface := &NetworkInterface{
            		interfaceName: interfaceName,
            		interfaceIpv4: addr.String(),
	            	interfaceIpv4Subnet: netw.String(),
	            	interfaceIpv4Gateway: gatewayIp.String(),
	            }
	            networkInterfaces = append(networkInterfaces, networkInterface)
            }
        }
    }

	return networkInterfaces, nil
}




type KillWorker struct {
	containerId string
}

func newKillWorker(containerId string) *KillWorker {
	return &KillWorker{
		containerId: containerId,
	}
}

func (self *KillWorker) run() {
	noRestartCommand := docker("update", "--restart=no", self.containerId)
	err := noRestartCommand.Run()
	if err != nil {
		panic(err)
	}

	stopCommand := docker("stop", "container", self.containerId)
	err = stopCommand.Run()
	if err != nil {
		panic(err)
	}
}


