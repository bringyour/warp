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
	"syscall"
	// "os/signal"

	"golang.org/x/exp/maps"

	"github.com/coreos/go-semver/semver"
)


const (
	MOUNT_MODE_NO = "no"
	MOUNT_MODE_YES = "yes"
	MOUNT_MODE_ROOT = "root"
)

const (
	STATUS_MODE_NO = "no"
	STATUS_MODE_STANDARD = "standard"
)


type RunWorker struct {
	warpState *WarpState
	dockerHubClient *DockerHubClient

	env string
	service string
	block string
	portBlocks *PortBlocks
	servicesDockerNetwork *DockerNetwork
	routingTable *RoutingTable
	dockerNetwork *DockerNetwork
	domain string

	vaultMountMode string
	configMountMode string
	siteMountMode string

	statusMode string
	statusPrefix string

	envVars map[string]string

	deployedVersion *semver.Version
	deployedConfigVersion *semver.Version

	quitEvent *Event
}

func (self *RunWorker) Run() {
	// on start, deploy the latest version and start the watcher loop

	self.quitEvent = NewEvent()

	closeFn := self.quitEvent.SetOnSignals(syscall.SIGQUIT, syscall.SIGTERM)
	defer closeFn()

	announceRunEnter()
	defer announceRunExit()

	// enable policy routing
	if self.routingTable != nil {
		self.initRoutingTable()
	}

	self.initBlockRedirect()

	self.deployedVersion = nil
	self.deployedConfigVersion = nil

	// watch for new versions until killed
	for !self.quitEvent.IsSet() {
		latestVersion, latestConfigVersion := self.getLatestVersion()
		Err.Printf("Polled latest versions: %s, %s\n", latestVersion, latestConfigVersion)

		deployVersion := func()(bool) {
			if latestVersion == nil {
				return false
			}
			if self.deployedVersion != nil && *self.deployedVersion == *latestVersion {
				return false
			}
			if self.configMountMode == MOUNT_MODE_NO {
				return true
			}
			if latestConfigVersion == nil {
				return false
			}
			if self.deployedConfigVersion != nil && *self.deployedConfigVersion == *latestConfigVersion {
				return false
			}
			return true
		}()

		if deployVersion {
			// deploy new version
			self.deployedVersion = latestVersion
			self.deployedConfigVersion = latestConfigVersion

			Err.Printf("Deploy version=%s, configVersion=%s\n", self.deployedVersion, self.deployedConfigVersion)
			func() {
				announceRunStart()
				defer func() {
					if err := recover(); err != nil {
						Err.Printf("Deploy error version=%s, configVersion=%s: %s\n", self.deployedVersion, self.deployedConfigVersion, err)
						announceRunError()
					}
				}()
				err := self.deploy()
				if err != nil {
					Err.Printf("Deploy fail version=%s, configVersion=%s: %s\n", self.deployedVersion, self.deployedConfigVersion, err)
					announceRunFail()
					// at this point, the previous version is still running
				} else {
					Err.Printf("Deploy success version=%s, configVersion=%s\n", self.deployedVersion, self.deployedConfigVersion)
					announceRunSuccess()
				}
			}()
			// prune stopped containers
			// this may not catch the draining containers from this epoch
			// it runs after each deploy to bound the number of stopped containers
			self.prune()
		} else if latestVersion == nil {
			announceRunWaitForVersion()
		} else if latestConfigVersion == nil {
			announceRunWaitForConfig()
		}

		self.quitEvent.WaitForSet(5 * time.Second)
	}
}

// service version, config version
func (self *RunWorker) getLatestVersion() (*semver.Version, *semver.Version) {
	versionMeta := self.dockerHubClient.getVersionMeta(self.env, self.service)
	latestVersion := versionMeta.latestBlocks[self.block]

	var latestConfigVersion *semver.Version
	if self.warpState.warpSettings.ConfigHome == nil {
		latestConfigVersion = nil
	} else {
		entries, err := os.ReadDir(*self.warpState.warpSettings.ConfigHome)
	    if err != nil {
	    	panic(err)
	    }

	    configVersions := []*semver.Version{}
	    for _, entry := range entries {
	    	if entry.IsDir() {
	    		if version, err := semver.NewVersion(entry.Name()); err == nil {
	    			configVersions = append(configVersions, version)
	    		}
	    	}
	    }
	    semverSortWithBuild(configVersions)

	    
	    if len(configVersions) == 0 {
	    	latestConfigVersion = nil
	    } else {
	    	latestConfigVersion = configVersions[len(configVersions) - 1]
	    }
	}

    return latestVersion, latestConfigVersion
}

func (self *RunWorker) initRoutingTable() {
	// ** important: restarting warpctl should not interrupt running services **
	// this does not remove routes/tables or rules to avoid interrupting running services
	// instead missing rules are added

	tableNumberStr := strconv.Itoa(self.routingTable.tableNumber)

	runAndLog(sudo(
		"ip", "route", "replace", self.routingTable.interfaceIpv4Subnet, 
		"dev", self.routingTable.interfaceName, 
		"src", self.routingTable.interfaceIpv4, 
		"table", tableNumberStr,
	))
    runAndLog(sudo(
    	"ip", "route", "replace", self.servicesDockerNetwork.interfaceIpv4Subnet, 
    	"dev", self.servicesDockerNetwork.interfaceName,
    	"src", self.servicesDockerNetwork.interfaceIpv4,
    	"table", tableNumberStr,
    ))
   	runAndLog(sudo(
   		"ip", "route", "replace", self.dockerNetwork.interfaceIpv4Subnet, 
    	"dev", self.dockerNetwork.interfaceName,
    	"src", self.dockerNetwork.interfaceIpv4,
    	"table", tableNumberStr,
    ))
   	runAndLog(sudo(
   		"ip", "route", "add", "default",
   		"via", self.routingTable.interfaceIpv4Gateway,
   		"dev", self.routingTable.interfaceName,
   		"table", tableNumberStr,
   	))

    /*
    32737:	from 172.19.0.0/16 lookup warp1
	32738:	from 192.168.208.1 lookup warp1
	32739:	from 172.19.0.0/16 lookup warp1
	32740:	from 192.168.208.1 lookup warp1
	*/
	ipRuleFromLookups := map[string]string{}
	ruleRegex := regexp.MustCompile("^\\s*.*\\s+from\\s+(\\S+)\\s+lookup\\s+(\\S+)\\s*$")
	if out, err := sudo(
		"ip", "rule", "list", "table", tableNumberStr,
	).Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			if groups := ruleRegex.FindStringSubmatch(line); groups != nil {
				from := groups[1]
				// `ip rule list table X` shows lookup table names not numbers
				tableName := groups[2]
				ipRuleFromLookups[from] = tableName
			}
		}
	}

	// lookup to the table for packets from these sources:
    // - interface ip (sockets bound to the interface)
    // - docker interface subnet (sockets in docker containers in the network)
	for _, from := range []string{
		self.routingTable.interfaceIpv4Gateway,
		self.dockerNetwork.interfaceIpv4Subnet,
	} {
		if tableName, ok := ipRuleFromLookups[from]; !ok || tableName != self.routingTable.tableName {
			runAndLog(sudo(
		   		"ip", "rule", "add",
		   		"from", from,
		   		"table", tableNumberStr,
		   	))
		}
	}
}

func (self *RunWorker) iptablesChainName() string {
	// iptables target names are 28 chars max
	maxLen := 28

	maxServiceLen := 10
	var shortService string
	if len(self.service) <= maxServiceLen {
		shortService = self.service
	} else if parts := strings.Split(self.service, "-"); 1 < len(parts) && len(parts) <= maxServiceLen / 2 {
		firstLetters := []string{}
		for _, part := range parts {
			if 0 < len(part) {
				firstLetters = append(firstLetters, part[:1])
			} else {
				firstLetters = append(firstLetters, "")
			}
		}
		shortService = strings.Join(firstLetters, "-")
	} else {
		shortService = self.service[:maxServiceLen]
	}

	var shortBlock string
	if self.service == "lb" {
		// use the interface name which is locally unique
		parts := strings.Split(self.block, "-")
		shortBlock = parts[len(parts) - 1]
	} else {
		shortBlock = self.block
	}

	chainName := fmt.Sprintf(
		"WARP-%s-%s-%s",
		strings.ToUpper(self.env),
		strings.ToUpper(shortService),
		strings.ToUpper(shortBlock),
	)
	if maxLen < len(chainName) {
		panic(fmt.Sprintf("iptables chain name cannot exceed %d chars", maxLen))
	}
	return chainName
}

func (self *RunWorker) initBlockRedirect() {
	// ** important: restarting warpctl should not interrupt running services **
	// add rules if they do not already exists

	chainName := self.iptablesChainName()

	// ignore errors
	runAndLog(sudo(
		"iptables", "-t", "nat", "-N", chainName,
	))
 
	chainCmd := func(op string, entryChainName string) *exec.Cmd {
		cmd := sudo(
			"iptables", "-t", "nat", op, entryChainName,
			"-m", "addrtype", "--dst-type", "LOCAL",
			"-j", chainName,
		)
		return cmd
	}

	// apply chain to external traffic to local
	// do not add if already exists
	if err := runAndLog(chainCmd("-C", "PREROUTING")); err != nil {
		if err := runAndLog(chainCmd("-I", "PREROUTING")); err != nil {
			panic(err)
		}
	}

	// apply chain to local traffic to local
	// do not add if already exists
	if err := runAndLog(chainCmd("-C", "OUTPUT")); err != nil {
		if err := runAndLog(chainCmd("-I", "OUTPUT")); err != nil {
			panic(err)
		}
	}
}

func (self *RunWorker) deploy() error {
	externalPortsToInternalPort, servicePortsToInternalPort := self.waitForDeployPorts()
	Err.Printf(
		"Ports %s, %s\n",
		mapStr(externalPortsToInternalPort),
		mapStr(servicePortsToInternalPort),
	)

    deployedContainerId, err := self.startContainer(servicePortsToInternalPort)
    if err != nil {
    	Err.Printf("Start container failed: %s\n", err)
    	return err
    }
    success := false
    defer func() {
		if !success {
	    	go NewKillWorker(deployedContainerId).Run()
	    }
    }()

	if err := self.pollContainerStatus(servicePortsToInternalPort, 30 * time.Second); err != nil {
		return err
	}

	runningContainers, err := self.findRunningContainers()
	if err != nil {
		return err
	}
	// verify the internal ports
	for _, internalPort := range servicePortsToInternalPort {
		if containerId, ok := runningContainers[internalPort]; !ok || deployedContainerId != containerId {
			return errors.New(fmt.Sprintf("Container is not listening on internal port %d", internalPort))
		}
	}

	// container_ids that overlap the owned ports
    containerIds := map[string]bool{}
    for _, internalPorts := range self.portBlocks.externalsToInternals {
    	for _, internalPort := range internalPorts {
    		if containerId, ok := runningContainers[internalPort]; ok {
    			containerIds[containerId] = true
    		}
    	}
    }
    Err.Printf("Found overlapping containers %s\n", strings.Join(maps.Keys(containerIds), ", "))
    for containerId, _ := range containerIds {
    	if containerId != deployedContainerId {
		    go NewKillWorker(containerId).Run()
		}
	}

    self.redirect(externalPortsToInternalPort)
    success = true
    return nil
}

func (self *RunWorker) waitForDeployPorts() (map[int]int, map[int]int) {
	for !self.quitEvent.IsSet() {
		externalPortsToInternalPort := map[int]int{}

		runningContainers, err := self.findRunningContainers()
		if err != nil {
			panic(err)
		}
		for externalPort, internalPorts := range self.portBlocks.externalsToInternals {
			for _, internalPort := range internalPorts {
				if _, ok := runningContainers[internalPort]; !ok {
					externalPortsToInternalPort[externalPort] = internalPort
					break
				}
			}
		}

		if len(externalPortsToInternalPort) < len(self.portBlocks.externalsToInternals) {
			self.quitEvent.WaitForSet(5 * time.Second)
		} else {
			servicePortsToInternalPort := map[int]int{}
			for externalPort, servicePort := range self.portBlocks.externalsToService {
				internalPort := externalPortsToInternalPort[externalPort]
				servicePortsToInternalPort[servicePort] = internalPort
			}

			return externalPortsToInternalPort, servicePortsToInternalPort
		}
	}
	panic("Could not allocate ports.")
}

func (self *RunWorker) startContainer(servicePortsToInternalPort map[int]int) (string, error) {
	vaultMount := "/srv/warp/vault"
	configMount := "/srv/warp/config"
	siteMount := "/srv/warp/site"

	containerName := fmt.Sprintf(
		"%s-%s-%s-%s-%d",
		self.env,
		self.service,
		self.block,
		convertVersionToDocker(self.deployedVersion.String()),
		time.Now().UnixMilli(),
	)
	imageName := fmt.Sprintf(
		"%s/%s-%s:%s",
		self.warpState.warpSettings.RequireDockerNamespace(),
		self.env,
		self.service,
		convertVersionToDocker(self.deployedVersion.String()),
	)

	pullCmd := docker("pull", imageName)
	err := runAndLog(pullCmd)
	if err != nil {
		return "", err
	}

	args := []string{
		"--label", fmt.Sprintf("%s-%s-%s", self.env, self.service, self.block),
		"--label", fmt.Sprintf("version=%s", convertVersionToDocker(self.deployedVersion.String())),
		"--name", containerName,
		"-d",
		"--restart=on-failure",
	}
	for servicePort, internalPort := range servicePortsToInternalPort {
		args = append(args, []string{"-p", fmt.Sprintf("%d:%d", internalPort, servicePort)}...)
	}
	if self.dockerNetwork != nil {
		args = append(args, []string{"--network", self.dockerNetwork.networkName}...)
	} else {
		args = append(args, []string{"--network", self.servicesDockerNetwork.networkName}...)
	}
	if self.dockerNetwork != nil {
		args = append(args, []string{"--add-host", fmt.Sprintf("%s:%s", self.dockerNetwork.networkName, self.dockerNetwork.interfaceIpv4)}...)
	}
	args = append(args, []string{"--add-host", fmt.Sprintf("%s:%s", self.servicesDockerNetwork.networkName, self.servicesDockerNetwork.interfaceIpv4)}...)

	switch self.vaultMountMode {
	case MOUNT_MODE_YES:
		args = append(args, []string{
			"--mount",
			fmt.Sprintf(
				"type=bind,source=%s,target=%s,readonly",
				self.warpState.warpSettings.RequireVaultHome(),
				vaultMount,
			),
		}...)
	}

	switch self.configMountMode {
	case MOUNT_MODE_YES:
		configVersionHome := path.Join(
			self.warpState.warpSettings.RequireConfigHome(),
			self.deployedConfigVersion.String(),
		)
		args = append(args, []string{
			"--mount",
			fmt.Sprintf(
				"type=bind,source=%s,target=%s,readonly",
				configVersionHome,
				configMount,
			),
		}...)
	case MOUNT_MODE_ROOT:
		// mount as read-write (default)
		args = append(args, []string{
			"--mount",
			fmt.Sprintf(
				"type=bind,source=%s,target=%s",
				self.warpState.warpSettings.RequireConfigHome(),
				configMount,
			),
		}...)
	}

	switch self.siteMountMode {
	case MOUNT_MODE_YES:
		args = append(args, []string{
			"--mount",
			fmt.Sprintf(
				"type=bind,source=%s,target=%s,readonly",
				self.warpState.warpSettings.RequireSiteHome(),
				siteMount,
			),
		}...)
	}

	env := map[string]string{
		"WARP_VERSION": self.deployedVersion.String(),
		"WARP_ENV": self.env,
		"WARP_SERVICE": self.service,
		"WARP_BLOCK": self.block,
	}
	if self.deployedConfigVersion != nil {
		env["WARP_CONFIG_VERSION"] = self.deployedConfigVersion.String()
	}
	if self.vaultMountMode != MOUNT_MODE_NO {
		env["WARP_VAULT"] = vaultMount
	}
	if self.configMountMode != MOUNT_MODE_NO {
		env["WARP_CONFIG"] = configMount
	}
	if self.siteMountMode != MOUNT_MODE_NO {
		env["WARP_SITE"] = siteMount
	}
	// add the user env vars
	for key, value := range self.envVars {
		env[key] = value
	}
	for name, value := range env {
		args = append(args, []string{"-e", fmt.Sprintf("%s=%s", name, value)}...)	
	}

	args = append(args, imageName)
	if self.service == "lb" {
		// the lb expects the path of the config to be given as an arg
		// TODO ideally this could be handled with an env var in the docker image, 
		// TODO but unfortunately docker does not allow env vars in the command
		args = append(args, fmt.Sprintf("/srv/warp/nginx.conf/%s.conf", self.block))
	}

	runCmd := docker("run", args...)

	out, err := runCmd.Output()
	if err != nil {
		return "", err
	}
	// `docker run` prints the container_id as the only output
	containerId := strings.TrimSpace(string(out))

	if self.dockerNetwork != nil {
		// connect to the services network
		docker("network", "connect",  self.servicesDockerNetwork.networkName, containerId)
	}

	return containerId, nil
}

func (self *RunWorker) pollContainerStatus(servicePortsToInternalPort map[int]int, timeout time.Duration) error {
	switch self.statusMode {
	case STATUS_MODE_STANDARD:
		return self.pollBasicContainerStatus(servicePortsToInternalPort, timeout)
	default:
		// wait 30s
		if !self.quitEvent.WaitForSet(30 * time.Second) {
			return nil
		}
		panic("Could not poll status.")
	}
}

func (self *RunWorker) pollBasicContainerStatus(servicePortsToInternalPort map[int]int, timeout time.Duration) error {
	httpPort, ok := servicePortsToInternalPort[80]
	if !ok {
		// no http port - assume ok
		return nil
	}

	client := &http.Client{}

	poll := func()(error) {
		var routePrefix string
		if self.statusPrefix == "" {
			routePrefix = ""
		} else {
			routePrefix = fmt.Sprintf("/%s", self.statusPrefix)
		}
		statusUrl := fmt.Sprintf("http://127.0.0.1:%d%s/status", httpPort, routePrefix)
		Err.Printf("Poll %s\n", statusUrl)

		statusRequest, err := http.NewRequest("GET", statusUrl, nil)
		if err != nil {
			return err
		}
		statusRequest.Host = fmt.Sprintf("%s-%s.%s", self.env, self.service, self.domain)
		statusResponse, err := client.Do(statusRequest)
		if err != nil {
			return err
		}
		body, err := io.ReadAll(statusResponse.Body)
		Err.Printf("Poll result %s (%s)\n", body, err)
	    if err != nil {
	    	return err
	    }
	    var warpStatusResponse WarpStatusResponse
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
	for !self.quitEvent.IsSet() {
		err := poll()
		if err == nil {
			return nil
		}
		if time.Now().After(endTime) {
			return err
		}
		self.quitEvent.WaitForSet(5 * time.Second)
	}
	panic("Could not poll container status.")
}

func (self *RunWorker) redirect(externalPortsToInternalPort map[int]int) {
	chainName := self.iptablesChainName()

	redirectCmd := func(op string, externalPort int, internalPort int) *exec.Cmd {
		return sudo(
	    	"iptables", "-t", "nat", op, chainName,
	    	"-p", "tcp", "-m", "tcp", "--dport", strconv.Itoa(externalPort),
	    	"-j", "REDIRECT", "--to-ports", strconv.Itoa(internalPort),
	    )
	}

	for externalPort, internalPort := range externalPortsToInternalPort {
		// do not add if already exists
		if err := runAndLog(redirectCmd("-C", externalPort, internalPort)); err != nil {
		    if err := runAndLog(redirectCmd("-I", externalPort, internalPort)); err != nil {
		    	panic(err)
		    }
		}
	}

	// find existing redirects and remove those for the owned external ports
	existingExternalPortsToInternalPorts := map[int]map[int]bool{}
	redirectRegex := regexp.MustCompile("^\\s*REDIRECT\\s+.*\\s+dpt:(\\d+)\\s+redir\\s+ports\\s+(\\d+)\\s*$")
	if out, err := sudo("iptables", "-t", "nat", "-L", chainName, "-n").Output(); err == nil {
		/*
		Chain WARP-LOCAL-LB-ENS160 (2 references)
		target     prot opt source               destination
		REDIRECT   tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:443 redir ports 7231
		REDIRECT   tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:80 redir ports 7201
		*/
		for _, line := range strings.Split(string(out), "\n") {
			if groups := redirectRegex.FindStringSubmatch(line); groups != nil {
				externalPort, _ := strconv.Atoi(groups[1])
				internalPort, _ := strconv.Atoi(groups[2])
				internalPortsMap, ok := existingExternalPortsToInternalPorts[externalPort]
				if !ok {
					internalPortsMap = map[int]bool{}
					existingExternalPortsToInternalPorts[externalPort] = internalPortsMap
				}
				internalPortsMap[internalPort] = true
			}
		}
	}

	Err.Printf("Remove existing redirects %s\n", existingExternalPortsToInternalPorts)

	for externalPort, internalPort := range externalPortsToInternalPort {
		if existingInternalPortsMap, ok := existingExternalPortsToInternalPorts[externalPort]; ok {
			for existingInternalPort, _ := range existingInternalPortsMap {
				if internalPort != existingInternalPort {
					for {
						cmd := redirectCmd("-D", externalPort, existingInternalPort)
		    			if err := runAndLog(cmd); err != nil {
		    				break
		    			}
		    		}
				}
			}
		}
	}
}

func (self *RunWorker) prune() {
	// ignore errors
	cmd := docker(
		"container",
		"prune",
		"-f",
		// restict to containers labeled with <env>-<service>-<block>
		"--filter", fmt.Sprintf("label=%s-%s-%s", self.env, self.service, self.block),
	)
	runAndLog(cmd)
}


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

// internal port -> running container_id for all running containers
func (self *RunWorker) findRunningContainers() (map[int]string, error) {
	psCmd := docker("ps", "--format", "{{.ID}}")
	out, err := psCmd.Output()
	if err != nil {
		return nil, err
	}

	outStr := strings.TrimSpace(string(out))
	if outStr == "" {
		// no containers running
		return map[int]string{}, nil
	}

	containerIds := strings.Split(outStr, "\n")
	inspectCmd := docker("inspect", containerIds...)
	out, err = inspectCmd.Output()
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
	externalsToService map[int]int
}

// service:external::p-P,p;service:external:...
func parsePortBlocks(portBlocksStr string) *PortBlocks {
	externalsToInternals := map[int][]int{}
	externalsToService := map[int]int{}

	externalStrs := strings.Split(portBlocksStr, ";")
	for _, externalStr := range externalStrs {
		externalStrSplit := strings.SplitN(externalStr, ":", 3)
		servicePort, err := strconv.Atoi(externalStrSplit[0])
		if err != nil {
			panic(fmt.Sprintf("Port block must be int serviceport:externalport:portlist (%s)", externalStrSplit[0]))
		}
		externalPort, err := strconv.Atoi(externalStrSplit[1])
		if err != nil {
			panic(fmt.Sprintf("Port block must be int serviceport:externalport:portlist (%s)", externalStrSplit[0]))
		}
		
		internalPorts, err := expandPorts(externalStrSplit[2])
		if err != nil {
			panic(err)
		}
		externalsToInternals[externalPort] = internalPorts
		externalsToService[externalPort] = servicePort
	}
	return &PortBlocks{
		externalsToInternals: externalsToInternals,
		externalsToService: externalsToService,
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
	if 1 < len(networkInterfaces) {
		panic(errors.New(fmt.Sprintf("More than one network attached to interface %s", interfaceName)))
	}
	networkInterface := networkInterfaces[0]

	return &DockerNetwork{
		networkName: dockerNetworkStr,
		NetworkInterface: *networkInterface,
	}
}


type RoutingTable struct {
	interfaceName string
	tableNumber int
	tableName string
	NetworkInterface
}

// interface:rt_table_name
// inspect the local interface for the ip address
func parseRoutingTable(routingTableStr string) *RoutingTable {
	routingTableStrSplit := strings.SplitN(routingTableStr, ":", 2)
	interfaceName := routingTableStrSplit[0]
	tableNumber, err := strconv.Atoi(routingTableStrSplit[1])
	if err != nil {
		panic(err)
	}

	tableNames := map[int]string{}
    tableNameRegex := regexp.MustCompile("^\\s*(\\d+)\\s+(\\S+)\\s*$")
    if out, err := os.ReadFile("/etc/iproute2/rt_tables"); err == nil {
    	for _, line := range strings.Split(string(out), "\n") {
			if groups := tableNameRegex.FindStringSubmatch(line); groups != nil {
				tableNumber, err := strconv.Atoi(groups[1])
				if err != nil {
					panic("Bad rt_tables entry.")
				}
				tableName := groups[2]
				tableNames[tableNumber] = tableName
			}
		}
    }
    
	tableName, ok := tableNames[tableNumber]
	if !ok {
		panic(fmt.Sprintf("Routing table %d does not exist.", tableNumber))
	}

	networkInterfaces, err := getNetworkInterfaces(interfaceName)
	if err != nil {
		panic(err)
	}
	if len(networkInterfaces) == 0 {
		panic(errors.New(fmt.Sprintf("Could not find interface %s", interfaceName)))
	}
	if 1 < len(networkInterfaces) {
		panic(errors.New(fmt.Sprintf("More than one network attached to interface %s", interfaceName)))
	}
	networkInterface := networkInterfaces[0]

	return &RoutingTable{
		interfaceName: interfaceName,
		tableNumber: tableNumber,
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
        if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() != nil {
        	zeroedIpNet := net.IPNet{
        		IP: ipNet.IP.Mask(ipNet.Mask),
        		Mask: ipNet.Mask,
        	}

        	gateway := nextIp(zeroedIpNet, 1)

        	networkInterface := &NetworkInterface{
        		interfaceName: interfaceName,
        		interfaceIpv4: ipNet.IP.String(),
            	interfaceIpv4Subnet: zeroedIpNet.String(),
            	interfaceIpv4Gateway: gateway.String(),
            }
            networkInterfaces = append(networkInterfaces, networkInterface)
        }
    }

    for _, networkInterface := range networkInterfaces {
    	Err.Printf(
    		"%s ipv4=%s ipv4_subnet=%s ipv4_gateway=%s\n",
    		networkInterface.interfaceName,
    		networkInterface.interfaceIpv4,
    		networkInterface.interfaceIpv4Subnet,
    		networkInterface.interfaceIpv4Gateway,
    	)
    }

	return networkInterfaces, nil
}


type KillWorker struct {
	containerId string
}

func NewKillWorker(containerId string) *KillWorker {
	return &KillWorker{
		containerId: containerId,
	}
}

func (self *KillWorker) Run() {
	// ignore errors
	runAndLog(docker(
		"update", "--restart=no", self.containerId,
	))

	// ignore errors
	runAndLog(docker(
		"stop", "container", "--time", "120", self.containerId,
	))
}


