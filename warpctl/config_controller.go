package main

import (
    "os"
    "fmt"
    "path/filepath"
    "errors"
    "strings"
    "sort"

    "golang.org/x/exp/maps"
    "golang.org/x/exp/slices"

    "gopkg.in/yaml.v3"
    "github.com/coreos/go-semver/semver"
)


type ServicesConfig struct {
    Domain string `yaml:"domain,omitempty"`
    CorsHost string `yaml:"core_host,omitempty"`
    HiddenPrefixes []string `yaml:"hidden_prefixes,omitempty"`
    LbHiddenPrefixes []string `yaml:"lb_hidden_prefixes,omitempty"`
    Versions []*ServicesConfigVersion `yaml:"versions,omitempty"`
}


func (self *ServicesConfig) getHiddenPrefix() string {
    if 0 < len(self.HiddenPrefixes) {
        return self.HiddenPrefixes[0]
    }
    return ""
}


func (self *ServicesConfig) getLbHiddenPrefix() string {
    if 0 < len(self.LbHiddenPrefixes) {
        return self.LbHiddenPrefixes[0]
    }
    if 0 < len(self.HiddenPrefixes) {
        return self.HiddenPrefixes[0]
    }
    return ""
}




type ServicesConfigVersion struct {
    ExternalPorts any `yaml:"external_ports,omitempty"`
    InternalPorts any `yaml:"internal_ports,omitempty"`
    RoutingTables any `yaml:"routing_tables,omitempty"`
    ParallelBlockCount int `yaml:"parallel_block_count,omitempty"`
    ServicesDockerNetwork string `yaml:"services_docker_network,omitempty"`

    Lb *LbConfig `yaml:"lb,omitempty"`
    Services map[string]*ServiceConfig `yaml:"services,omitempty"`
}


type PortConfig struct {
    Ports []int `yaml:"ports,omitempty"`
    UdpPorts []int `yaml:"udp_ports,omitempty"`
}

func (self *PortConfig) AllPorts() map[string][]int {
    return map[string][]int {
        "tcp": self.Ports,
        "udp": self.UdpPorts,
    }
}


type LbConfig struct {
    Interfaces map[string]map[string]*LbBlock `yaml:"interfaces,omitempty"`
    // see https://github.com/go-yaml/yaml/issues/63
    PortConfig `yaml:",inline"`
}


type ServiceConfig struct {
    ExposeAliases []string `yaml:"expose_aliases,omitempty"`
    Exposed *bool `yaml:"exposed,omitempty"`
    LbExposed *bool `yaml:"lb_exposed,omitempty"`
    Hosts []string `yaml:"hosts,omitempty"`
    Blocks []map[string]int `yaml:"blocks,omitempty"`
    // see https://github.com/go-yaml/yaml/issues/63
    PortConfig `yaml:",inline"`
}

func (self *ServiceConfig) isExposed() bool {
    // default true
    return self.Exposed == nil || *self.Exposed
}

func (self *ServiceConfig) isLbExposed() bool {
    return self.LbExposed == nil || *self.LbExposed
}


func (self *ServiceConfig) includesHost(host string) bool {
    return len(self.Hosts) == 0 || slices.Contains(self.Hosts, host)
}




type LbBlock struct {
    DockerNetwork string `yaml:"docker_network,omitempty"`
    ConcurrentClients int `yaml:"concurrent_clients,omitempty"`
    Cores int `yaml:"cores,omitempty"`
    ExternalPorts map[int]int `yaml:"external_ports,omitempty"`
}











// load from the vaulthome
func getServicesConfig(env string) *ServicesConfig {

    state := getWarpState()

servicesConfigPath := filepath.Join(
        state.warpSettings.RequireVaultHome(),
        env,
        "services.yml",
    )
    data, err := os.ReadFile(servicesConfigPath)
    if err != nil {
        panic(err)
    }

    var servicesConfig ServicesConfig
    err = yaml.Unmarshal(data, &servicesConfig)
    if err != nil {
        panic(err)
    }

    // add a default config-updater if not defined
    if _, ok := servicesConfig.Versions[0].Services["config-updater"]; !ok {
        exposed := false
        lbExposed := false
        servicesConfig.Versions[0].Services["config-updater"] = &ServiceConfig{
            Exposed: &exposed,
            LbExposed: &lbExposed,
            Blocks: []map[string]int{
                map[string]int{"main":1},
            },
        }
    }

    return &servicesConfig
}






// union lb and service blocks
type BlockInfo struct {
    service string
    block string
    weight int

    host string
    interfaceName string
    lbBlock *LbBlock
}



// service -> blockinfo
func getBlockInfos(env string) map[string]map[string]*BlockInfo {
    servicesConfig := getServicesConfig(env)

    blockInfos := map[string]map[string]*BlockInfo{}
    
    lbBlockInfos := map[string]*BlockInfo{}
    for host, lbBlocks := range servicesConfig.Versions[0].Lb.Interfaces {
        for interfaceName, lbBlock := range lbBlocks {
            block := fmt.Sprintf("%s-%s", host, interfaceName)
            blockInfo := &BlockInfo{
                service: "lb",
                block: block,
                host: host,
                interfaceName: interfaceName,
                lbBlock: lbBlock,
            }
            lbBlockInfos[block] = blockInfo
        }
    }
    blockInfos["lb"] = lbBlockInfos

    for service, serviceConfig := range servicesConfig.Versions[0].Services {
        serviceBlockInfos := map[string]*BlockInfo{}
        for _, blockWeights := range serviceConfig.Blocks {
            blocks := maps.Keys(blockWeights)
            sort.Strings(blocks)
            for _, block := range blocks {
                weight := blockWeights[block]
                blockInfo := &BlockInfo {
                    service: service,
                    block: block,
                    weight: weight,
                }
                serviceBlockInfos[block] = blockInfo
            }
        }
        blockInfos[service] = serviceBlockInfos
    }

    return blockInfos
}

func getBlocks(env string, service string) []string {
    blockInfos := getBlockInfos(env)
    blocks := []string{}
    for block, _ := range blockInfos[service] {
        blocks = append(blocks, block)
    }
    return blocks
}




type PortBlock struct {
    service string
    block string
    port int
    externalPort int
    externalPortType string
    internalPorts []int
    routingTable int
}

func (self *PortBlock) eq(service string, block string, port int) bool {
    return self.service == service && self.block == block && self.port == port
}


// service -> block -> port -> block
// port block is external port:service port:internal port range
func getPortBlocks(env string) map[string]map[string]map[int]*PortBlock {
    /*
    # RULES:
# 1. Once an internal port is associated to a service-block, it can never be associated to another service-block.
# 2. Each service-block-<serviceport> has a fixed external port that will never change.
#    If the port is removed from the exteral ports list, that is a config error.
# 3. An lb-block has a fixed routing table that will never change
*/

    servicesConfig := getServicesConfig(env)


    portBlocks := map[string]map[string]map[int]*PortBlock{}
    assignedExternalPorts := map[int]*PortBlock{}
    assignedInternalPorts := map[int]*PortBlock{}
    assignedLbRoutingTables := map[int]string{}


    assignPortBlock := func(service string, block string, port int)(*PortBlock) {
        fmt.Printf("ASSIGN PORT BLOCK %s %s %d\n", service, block, port)
        portBlock, ok := portBlocks[service][block][port]
        if ok {
            return portBlock
        }
        portBlock = &PortBlock{
            service: service,
            block: block,
            port: port,
        }
        if _, ok := portBlocks[service]; !ok {
            portBlocks[service] = map[string]map[int]*PortBlock{}
        }
        if _, ok := portBlocks[service][block]; !ok {
            portBlocks[service][block] = map[int]*PortBlock{}
        }
        portBlocks[service][block][port] = portBlock
        return portBlock
    }

    assignExternalPort := func(
        service string,
        block string,
        port int,
        externalPorts []int,
        force map[int]int,
        externalPortType string,
    ) {
        portBlock := assignPortBlock(service, block, port)
        
        p := func()(int) {
            for p, servicePort := range force {
                if port == servicePort {
                    return p
                }
            }

            // find an already assigned port
            for _, p := range externalPorts {
                if assignedPortBlock, ok := assignedExternalPorts[p]; ok {
                    if assignedPortBlock.eq(service, block, port) {
                        return p
                    }
                }
            }

            // find a free port
            for _, p := range externalPorts {
                if _, ok := assignedExternalPorts[p]; !ok {
                    return p
                }
            }

            panic("No more external ports to assign. Increase the external port range.")
        }()

        if portBlock.externalPort != 0 && portBlock.externalPort != p {
            panic("The external port of a port block cannot change.")
        }
        if portBlock.externalPortType != "" && portBlock.externalPortType != externalPortType {
            panic("The external port type of a port block cannot change.")
        }

        if assignedPortBlock, ok := assignedExternalPorts[p]; ok {
            if !assignedPortBlock.eq(service, block, port) {
                panic("Cannot overwrite the external port of another port block.")
            }
        }
        assignedExternalPorts[p] = portBlock

        portBlock.externalPort = p
        portBlock.externalPortType = externalPortType

        fmt.Printf("ASSIGNED EXTERNAL PORT %s %s %d -> %d\n", service, block, port, p)
    }
    assignInternalPorts := func(
        service string,
        block string,
        port int,
        internalPorts []int,
        count int,
    ) {
        portBlock := assignPortBlock(service, block, port)
        
        ps := []int{}

        // find already assigned ports
        for _, p := range internalPorts {
            if count <= len(ps) {
                break
            }
            if assignedPortBlock, ok := assignedInternalPorts[p]; ok {
                if assignedPortBlock.eq(service, block, port) {
                    ps = append(ps, p)
                }
            }
        }

        // find free ports
        for _, p := range internalPorts {
            if count <= len(ps) {
                break
            }
            if _, ok := assignedInternalPorts[p]; !ok {
                ps = append(ps, p)
            }
        }

        if len(ps) < count {
            panic("No more internal ports to assign. Increase the internal port range.")
        }

        for _, p := range ps {
            if assignedPortBlock, ok := assignedInternalPorts[p]; ok {
                if !assignedPortBlock.eq(service, block, port) {
                    panic("Cannot overwrite the internal port of another port block.")
                }
            }
            assignedInternalPorts[p] = portBlock
        }
        portBlock.internalPorts = ps
    }
    assignLbRoutingTable := func(
        block string,
        routingTables []int,
    ) {
        rt := func()(int) {
            // find an already routing table
            for _, rt := range routingTables {
                if assignedBlock, ok := assignedLbRoutingTables[rt]; ok {
                    if assignedBlock == block {
                        return rt
                    }
                }
            }

            // find a free routing table
            for _, rt := range routingTables {
                if _, ok := assignedLbRoutingTables[rt]; !ok {
                    return rt
                }
            }

            panic("No more routing tables to assign. Increase the routing table range.")
        }()

        // search all the routing tables
        for assignedRt, assignedBlock := range assignedLbRoutingTables {
            if assignedBlock == block {
                if assignedRt != rt {
                    panic("The routing table of a block cannot change.")
                }
            }
        }

        assignedLbRoutingTables[rt] = block
    }


    // interate versions from last to first
    for i := len(servicesConfig.Versions) - 1; 0 <= i; i -= 1 {
        serviceConfigVersion := servicesConfig.Versions[i]
        externalPorts, err := expandAnyPorts(serviceConfigVersion.ExternalPorts)
        if err != nil {
            panic(err)
        }
        internalPorts, err := expandAnyPorts(serviceConfigVersion.InternalPorts)
        if err != nil {
            panic(err)
        }
        routingTables, err := expandAnyPorts(serviceConfigVersion.RoutingTables)
        if err != nil {
            panic(err)
        }

        lbConfig := serviceConfigVersion.Lb
        // process forced external ports first
        for _, includeForcedExternalPorts := range []bool{true, false} {
            for host, lbBlocks := range lbConfig.Interfaces {
                for interfaceName, lbBlock := range lbBlocks {
                    hasForcedExternalPorts := 0 < len(lbBlock.ExternalPorts)
                    if hasForcedExternalPorts != includeForcedExternalPorts {
                        continue
                    }

                    block := fmt.Sprintf("%s-%s", host, interfaceName)

                    assignLbRoutingTable(
                        block,
                        routingTables,
                    )

                    for portType, ports := range lbConfig.AllPorts() {
                        fmt.Printf("ASSIGNING PORTS %s %s (%s)\n", portType, ports, lbBlock.ExternalPorts)
                        for _, port := range ports {
                            assignExternalPort(
                                "lb",
                                block,
                                port,
                                externalPorts,
                                lbBlock.ExternalPorts,
                                portType,
                            )
                            assignInternalPorts(
                                "lb",
                                block,
                                port,
                                internalPorts,
                                serviceConfigVersion.ParallelBlockCount,
                            )
                        }
                    }
                }
            }
        }
        // join back the lb routing tables
        for routingTable, block := range assignedLbRoutingTables {
            for _, portBlock := range portBlocks["lb"][block] {
                portBlock.routingTable = routingTable
            }
        }

        for service, serviceConfig := range serviceConfigVersion.Services {
            for _, blockWeights := range serviceConfig.Blocks {
                for block, _ := range blockWeights {
                    for portType, ports := range serviceConfig.AllPorts() {
                        for _, port := range ports {
                            assignExternalPort(
                                service,
                                block,
                                port,
                                externalPorts,
                                map[int]int{},
                                portType,
                            )
                            assignInternalPorts(
                                service,
                                block,
                                port,
                                internalPorts,
                                serviceConfigVersion.ParallelBlockCount,
                            )
                        }
                    }
                }
            }
        }
    }

    return portBlocks
}











func getDomain(env string) string {
    servicesConfig := getServicesConfig(env)
    return servicesConfig.Domain
}

func getHostnames(env string, envAliases []string) []string {
    servicesConfig := getServicesConfig(env)

    hosts := []string{}

    lbHost := fmt.Sprintf("%s-lb.%s", env, servicesConfig.Domain)
    hosts = append(hosts, lbHost)

    for _, envAlias := range envAliases {
        lbHostAlias := fmt.Sprintf("%s-lb.%s", envAlias, servicesConfig.Domain)
        hosts = append(hosts, lbHostAlias)
    }   

    serviceConfigs := servicesConfig.Versions[0].Services
    services := maps.Keys(serviceConfigs)
    sort.Strings(services)

    for _, service := range services {
        serviceConfig := serviceConfigs[service]
        if !serviceConfig.isExposed() {
            continue
        }

        serviceHost := fmt.Sprintf("%s-%s.%s", env, service, servicesConfig.Domain)
        hosts = append(hosts, serviceHost)

        for _, envAlias := range envAliases {
            serviceHostAlias := fmt.Sprintf("%s-%s.%s", envAlias, service, servicesConfig.Domain)
            hosts = append(hosts, serviceHostAlias)
        }

        for _, serviceHostAlias := range serviceConfig.ExposeAliases {
            hosts = append(hosts, serviceHostAlias)
        }
    }

    return hosts
}


func isExposed(env string, service string) bool {
    servicesConfig := getServicesConfig(env)
    serviceConfig, ok := servicesConfig.Versions[0].Services[service]
    if !ok {
        // doesn't exist
        return false
    }
    return serviceConfig.isExposed()
}

func isLbExposed(env string, service string) bool {
    servicesConfig := getServicesConfig(env)
    serviceConfig, ok := servicesConfig.Versions[0].Services[service]
    if !ok {
        // doesn't exist
        return false
    }
    return serviceConfig.isLbExposed()
}

func getHiddenPrefix(env string) string {
    servicesConfig := getServicesConfig(env)
    return servicesConfig.getHiddenPrefix()
}

func getLbHiddenPrefix(env string) string {
    servicesConfig := getServicesConfig(env)
    return servicesConfig.getLbHiddenPrefix()
}






type NginxConfig struct {
    env string
    envAliases []string
    servicesConfig *ServicesConfig
    portBlocks map[string]map[string]map[int]*PortBlock
    blockInfos map[string]map[string]*BlockInfo
    // services []string

    relativeTlsPemPath string
    relativeTlsKeyPath string

    indent int

    // lbBlockHost string
    // lbBlockInterface string
    lbBlockInfo *BlockInfo
    configParts []string
}

func NewNginxConfig(env string, envAliases []string) *NginxConfig {
    servicesConfig := getServicesConfig(env)

    // note that all aliases must be covered by the same tls cert as the main domain
    relativeTlsPemPath, relativeTlsKeyPath := findLatestTls(servicesConfig.Domain)

    return &NginxConfig{
        env: env,
        envAliases: envAliases,
        servicesConfig: servicesConfig,
        portBlocks: getPortBlocks(env),
        blockInfos: getBlockInfos(env),
        relativeTlsPemPath: relativeTlsPemPath,
        relativeTlsKeyPath: relativeTlsKeyPath,
    }
}


func findLatestTls(domain string) (relativeTlsPemPath string, relativeTlsKeyPath string) {
    state := getWarpState()
    vaultHome := state.warpSettings.RequireVaultHome()
    // tlsHome := filepath.Join(vaultHome, "tls")

    domainSuffix := strings.ReplaceAll(domain, ".", "_")

    keyDirName := fmt.Sprintf("star_%s", domainSuffix)
    pemFileName := fmt.Sprintf("star_%s.pem", domainSuffix)
    keyFileName := fmt.Sprintf("star_%s.key", domainSuffix)

    hasTlsFiles := func(dirPath string)(bool) {
        fmt.Printf("TLS SEARCHING %s\n", dirPath)
        for _, fileName := range []string{pemFileName, keyFileName} {
            if _, err := os.Stat(filepath.Join(dirPath, keyDirName, fileName)); errors.Is(err, os.ErrNotExist) {
                return false
            }
        }
        return true
    }

    entries, err := os.ReadDir(filepath.Join(vaultHome, "tls"))
    if err != nil {
        panic(err)
    }
    versionDirNames := map[*semver.Version]string{}
    for _, entry := range entries {
        if entry.IsDir() {
            if version, err := semver.NewVersion(entry.Name()); err == nil {
                if hasTlsFiles(filepath.Join(vaultHome, "tls", entry.Name())) {
                    versionDirNames[version] = entry.Name()
                }
            }
        }
    }

    versions := maps.Keys(versionDirNames)
    semverSortWithBuild(versions)
    if 0 < len(versions) {
        version := versions[len(versions) - 1]
        versionDirName := versionDirNames[version]
        relativeTlsPemPath = filepath.Join("tls", versionDirName, keyDirName, pemFileName)
        relativeTlsKeyPath = filepath.Join("tls", versionDirName, keyDirName, keyFileName)
        return
    }

    // no version
    if hasTlsFiles(vaultHome) {
        relativeTlsPemPath = pemFileName
        relativeTlsKeyPath = keyFileName
        return
    }

    panic(fmt.Sprintf("TLS files %s and %s not found.", pemFileName, keyFileName))
}


func (self *NginxConfig) services() []string {
    // filter services based on which ones are exposed to the lbBlockInfo.host

    services := []string{}
    for service, serviceConfig := range self.servicesConfig.Versions[0].Services {
        if serviceConfig.includesHost(self.lbBlockInfo.host) {
            services = append(services, service)
        }
    }
    sort.Strings(services)
    return services
}


func (self *NginxConfig) raw(text string, data ...map[string]any) {
    configPart := indentAndTrimString(templateString(text, data...), self.indent)
    self.configParts = append(self.configParts, configPart)
}

func (self *NginxConfig) block(tag string, body func()) {
    open := indentAndTrimString(fmt.Sprintf("%s {", tag), self.indent)
    close := indentAndTrimString("}", self.indent)
    self.configParts = append(self.configParts, open)
    self.indent += 4
    body()
    self.indent -= 4
    self.configParts = append(self.configParts, close)
}

// lb block -> config
func (self *NginxConfig) generate() map[string]string {
    blockConfigs := map[string]string{}

    for block, blockInfo := range self.blockInfos["lb"] {
        fmt.Printf("GENERATING FOR BLOCK %s\n", block)
        self.indent = 0
        self.configParts = []string{}
        self.lbBlockInfo = blockInfo
        self.addNginxConfig()
        nginxConfig := strings.Join(self.configParts, "\n")
        self.configParts = nil
        self.lbBlockInfo = nil
        blockConfigs[block] = nginxConfig
    }

    return blockConfigs
}

func (self *NginxConfig) addNginxConfig() {
    self.raw(`
    user www-data;
    pid /run/nginx.pid;
    include /etc/nginx/modules-enabled/*.conf;
    `)

    concurrentClients := self.lbBlockInfo.lbBlock.ConcurrentClients
    cores := self.lbBlockInfo.lbBlock.Cores
    // round up
    workersPerCore := (concurrentClients + cores - 1) / cores

    self.raw(`
    # target concurrent users (from services.yml): {{.concurrentClients}}
    # https://www.nginx.com/blog/tuning-nginx/
    worker_processes {{.cores}};
    events {
        worker_connections {{.workersPerCore}};
        multi_accept on;
    }
    `, map[string]any{
        "concurrentClients": concurrentClients,
        "cores": cores,
        "workersPerCore": workersPerCore,
    })

    self.block("http", func(){
        self.raw(`
        ##
        # Basic Settings
        ##

        sendfile on;
        # minimize latency
        tcp_nodelay on;
        tcp_nopush off;
        types_hash_max_size 2048;
        server_tokens off;

        include /etc/nginx/mime.types;
        default_type application/octet-stream;

        ##
        # SSL Settings
        ##

        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_prefer_server_ciphers on;
        # see https://syslink.pl/cipherlist/
        ssl_dhparam /etc/nginx/dhparam.pem; # openssl dhparam -out /etc/nginx/dhparam.pem 4096
        ssl_ciphers EECDH+AESGCM:EDH+AESGCM;
        ssl_ecdh_curve secp384r1; # Requires nginx >= 1.1.0
        ssl_session_timeout  10m;
        ssl_session_cache shared:SSL:10m;
        ssl_session_tickets off; # Requires nginx >= 1.5.9
        ssl_stapling on; # Requires nginx >= 1.3.7
        ssl_stapling_verify on; # Requires nginx => 1.3.7
        resolver 1.1.1.1 1.0.0.1 valid=300s;
        resolver_timeout 5s;
        add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";
        add_header X-Frame-Options DENY;
        add_header X-Content-Type-Options nosniff;
        add_header X-XSS-Protection "1; mode=block";

        ##
        # Logging Settings
        ##

        access_log /var/log/nginx/access.log;
        error_log /var/log/nginx/error.log;

        ##
        # Gzip Settings
        ##

        gzip on;
        `)
        
        self.addUpstreamBlocks()

        // rate limiters
        self.raw(`
        # see https://www.nginx.com/blog/rate-limiting-nginx/
        limit_req_zone $binary_remote_addr zone=standardlimit:128m rate=5r/s;
        `)

        self.block("server", func() {
            self.raw(`
            listen 80 default_server;
            server_name _;

            location / {
                deny all;
            }
            `)
        })

        self.addLbBlock()

        self.addServiceBlocks()
    })

    // FIXME stream block
    // FIXME for non-80 ports, for each service port, we would match the service port of the lb to the external ports
    // 
}



func (self *NginxConfig) addUpstreamBlocks() {
    // service-block-<service>
    // service-block-<service>-<block>
    for _, service := range self.services() {
        // only service port 80 is exposed via the html block
        if !slices.Contains(self.servicesConfig.Versions[0].Services[service].Ports, 80) {
            continue
        }

        fmt.Printf("PORT BLOCKS %s\n", self.portBlocks)

        blocks := maps.Keys(self.portBlocks[service])
        sort.Strings(blocks)

        upstream := templateString(
            `upstream service-block-{{.service}}`,
            map[string]any{
                "service": service,
            },
        )

        self.block(upstream, func() {
            for _, block := range blocks {
                portBlock, ok := self.portBlocks[service][block][80]
                if !ok {
                    panic("Port block for service port 80 should have been defined.")
                }
                blockInfo := self.blockInfos[service][block]

                upstreamServer := templateString("server {{.dockerNetwork}}:{{.externalPort}} weight={{.weight}};",
                    map[string]any{
                        "dockerNetwork": self.servicesConfig.Versions[0].ServicesDockerNetwork,
                        "externalPort": portBlock.externalPort,
                        "weight": blockInfo.weight,
                    },
                )
                self.raw(upstreamServer)
            }

            self.raw(`
            keepalive 1024;
            keepalive_requests 1024;
            keepalive_time 30s;
            keepalive_timeout 30s;
            `)
        })

        for _, block := range blocks {
            portBlock, ok := self.portBlocks[service][block][80]
            if !ok {
                panic("Port block for service port 80 should have been defined.")
            }

            blockUpstream := templateString(
                `upstream service-block-{{.service}}-{{.block}}`,
                map[string]any{
                    "service": service,
                    "block": block,
                },
            )

            self.block(blockUpstream, func() {
                self.raw(`
                    server {{.dockerNetwork}}:{{.externalPort}};

                    keepalive 1024;
                    keepalive_requests 1024;
                    keepalive_time 30s;
                    keepalive_timeout 30s;
                `, map[string]any{
                    "dockerNetwork": self.servicesConfig.Versions[0].ServicesDockerNetwork,
                    "externalPort": portBlock.externalPort,
                })
            })
        }
    }
}



func (self *NginxConfig) addLbBlock() {
    var rootPrefix string
    lbHiddenPrefix := self.servicesConfig.getLbHiddenPrefix()
    if lbHiddenPrefix == "" {
        rootPrefix = ""
    } else {
        rootPrefix = fmt.Sprintf("/%s", lbHiddenPrefix)
    }

    

    lbHosts := []string{}

    lbHost := fmt.Sprintf("%s-lb.%s", self.env, self.servicesConfig.Domain)
    lbHosts = append(lbHosts, lbHost)

    for _, env := range self.envAliases {
        lbHostAlias := fmt.Sprintf("%s-lb.%s", env, self.servicesConfig.Domain)
        lbHosts = append(lbHosts, lbHostAlias)
    }

    // self.raw(`
    // server {
    //     listen 80;
    //     server_name {{.lbHostList}};
    //     return 301 https://$host$request_uri;
    // }
    // server {
    //     listen 443 ssl;
    //     server_name {{.lbHostList}};
    //     ssl_certificate     /srv/warp/vault/{{.relativeTlsPemPath}};
    //     ssl_certificate_key /srv/warp/vault/{{.relativeTlsKeyPath}};

    // {{.locations}}
    // }
    // `, map[string]any{
    //  "lbHostList": strings.Join(lbHosts, " "),
    //  "relativeTlsPemPath": self.relativeTlsPemPath,
    //  "relativeTlsKeyPath": self.relativeTlsKeyPath,
    //  "locations": strings.Join(locations, "\n"),
    // })

    self.block("server", func() {
        self.raw(`
        listen 80;
        server_name {{.lbHostList}};
        `, map[string]any{
            "lbHostList": strings.Join(lbHosts, " "),
        })

        self.block("location =/status", func() {
            self.raw(`
            root /srv/warp/status/;
            add_header Content-Type application/json;
            `, map[string]any{})
        })

        self.block("location /", func() {
            self.raw(`
            return 301 https://$host$request_uri;
            `, map[string]any{})
        })
    })

    self.block("server", func() {
        self.raw(`
        listen 443 ssl;
        server_name {{.lbHostList}};
        ssl_certificate     /srv/warp/vault/{{.relativeTlsPemPath}};
        ssl_certificate_key /srv/warp/vault/{{.relativeTlsKeyPath}};
        `, map[string]any{
            "lbHostList": strings.Join(lbHosts, " "),
            "relativeTlsPemPath": self.relativeTlsPemPath,
            "relativeTlsKeyPath": self.relativeTlsKeyPath,
        })

        self.block("location =/status", func() {
            self.raw(`
            root /srv/warp/status/;
            add_header Content-Type application/json;
            `, map[string]any{})
        })

        // /by/service/{service}/
        // /by/b/{service}/{name}/

        for _, service := range self.services() {
            if !self.servicesConfig.Versions[0].Services[service].isLbExposed() {
                continue
            }

            blocks := maps.Keys(self.portBlocks[service])
            sort.Strings(blocks)

            serviceHost := fmt.Sprintf("%s-%s.%s", self.env, service, self.servicesConfig.Domain)

            location := templateString(
                `location {{.rootPrefix}}/by/service/{{.service}}/`,
                map[string]any{
                    "rootPrefix": rootPrefix,
                    "service": service,
                },
            )

            self.block(location, func() {
                self.raw(`
                limit_req zone=standardlimit burst=50 delay=25;
                proxy_pass http://service-block-{{.service}}/;
                proxy_set_header X-Forwarded-For $remote_addr;
                proxy_set_header Host {{.serviceHost}};
                `, map[string]any{
                    "service": service,
                    "serviceHost": serviceHost,
                })
            })
            
            for _, block := range blocks {
                blockLocation := templateString(
                    `location {{.rootPrefix}}/by/b/{{.service}}/{{.block}}/`,
                    map[string]any{
                        "rootPrefix": rootPrefix,
                        "service": service,
                        "block": block,
                    },
                )

                self.block(blockLocation, func() {
                    self.raw(`
                    limit_req zone=standardlimit burst=50 delay=25;
                    proxy_pass http://service-block-{{.service}}-{{.block}}/;
                    proxy_set_header X-Forwarded-For $remote_addr;
                    proxy_set_header Host {{.serviceHost}};
                    `, map[string]any{
                        "service": service,
                        "block": block,
                        "serviceHost": serviceHost,
                    })
                })
            }
        }
    })
}

func (self *NginxConfig) addServiceBlocks() {
    var rootPrefix string
    hiddenPrefix := self.servicesConfig.getHiddenPrefix()
    if hiddenPrefix == "" {
        rootPrefix = ""
    } else {
        rootPrefix = fmt.Sprintf("/%s", hiddenPrefix)
    }

    for _, service := range self.services() {
        if !self.servicesConfig.Versions[0].Services[service].isExposed() {
            continue
        }

        serviceHosts := []string{}

        serviceHost := fmt.Sprintf("%s-%s.%s", self.env, service, self.servicesConfig.Domain)
        serviceHosts = append(serviceHosts, serviceHost)

        for _, env := range self.envAliases {
            serviceHostAlias := fmt.Sprintf("%s-%s.%s", env, service, self.servicesConfig.Domain)
            serviceHosts = append(serviceHosts, serviceHostAlias)
        }

        for _, serviceHostAlias := range self.servicesConfig.Versions[0].Services[service].ExposeAliases {
            serviceHosts = append(serviceHosts, serviceHostAlias)
        }

        self.block("server", func() {
            self.raw(`
            listen 80;
            server_name {{.serviceHostList}};
            return 301 https://$host$request_uri;
            `, map[string]any{
                "serviceHostList": strings.Join(serviceHosts, " "),
            })
        })

        self.block("server", func() {
            self.raw(`
            listen 443 ssl;
            server_name {{.serviceHostList}};
            ssl_certificate     /srv/warp/vault/{{.relativeTlsPemPath}};
            ssl_certificate_key /srv/warp/vault/{{.relativeTlsKeyPath}};

            location {{.rootPrefix}}/ {
                limit_req zone=standardlimit burst=50 delay=25;
                proxy_pass http://service-block-{{.service}}/;
                proxy_set_header X-Forwarded-For $remote_addr;

                # see https://enable-cors.org/server_nginx.html
                if ($request_method = 'OPTIONS') {
                    add_header 'Access-Control-Allow-Origin' 'https://{{.corsHost}}';
                    add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS';
                    #
                    # Custom headers and headers various browsers *should* be OK with but aren't
                    #
                    add_header 'Access-Control-Allow-Headers' 'DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,X-Client-Version';
                    #
                    # Tell client that this pre-flight info is valid for 20 days
                    #
                    add_header 'Access-Control-Max-Age' 1728000;
                    add_header 'Content-Type' 'text/plain; charset=utf-8';
                    add_header 'Content-Length' 0;
                    return 204;
                 }
                 if ($request_method = 'POST') {
                    add_header 'Access-Control-Allow-Origin' 'https://{{.corsHost}}' always;
                    add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS' always;
                    add_header 'Access-Control-Allow-Headers' 'DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,X-Client-Version' always;
                    add_header 'Access-Control-Expose-Headers' 'Content-Length,Content-Range' always;
                 }
                 if ($request_method = 'GET') {
                    add_header 'Access-Control-Allow-Origin' 'https://{{.corsHost}}' always;
                    add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS' always;
                    add_header 'Access-Control-Allow-Headers' 'DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,X-Client-Version' always;
                    add_header 'Access-Control-Expose-Headers' 'Content-Length,Content-Range' always;
                 }
            }
            `, map[string]any{
                "serviceHostList": strings.Join(serviceHosts, " "),
                "relativeTlsPemPath": self.relativeTlsPemPath,
                "relativeTlsKeyPath": self.relativeTlsKeyPath,
                "rootPrefix": rootPrefix,
                "service": service,
                "corsHost": self.servicesConfig.CorsHost,
            })
        })
    }
}




type SystemdUnits struct {
    env string
    targetWarpHome string
    targetWarpctl string
    servicesConfig *ServicesConfig
    portBlocks map[string]map[string]map[int]*PortBlock
    blockInfos map[string]map[string]*BlockInfo
}

func NewSystemdUnits(env string, targetWarpHome string, targetWarpctl string) *SystemdUnits {
    servicesConfig := getServicesConfig(env)

    return &SystemdUnits{
        env: env,
        targetWarpHome: targetWarpHome,
        targetWarpctl: targetWarpctl,
        servicesConfig: servicesConfig,
        portBlocks: getPortBlocks(env),
        blockInfos: getBlockInfos(env),
    }
}

// service -> block -> unit
func (self *SystemdUnits) generate() map[string]map[string]string {

    /*
    warpctl service run <env> <service> <block>
        [--rttable=<rttable> --dockernet=<dockernet>]
        [--portblocks=<portblocks>]
        --services_dockernet=<services_dockernet>
        [--mount_vault=<mount_vault_mode>]
        [--mount_config=<mount_config_mode>]
        [--mount_site=<mount_site_mode>]
    */

    /*
[Unit]
Description=Warpctl service <service> block <block>
Requires=network.target
After=network.target
Requires=docker.service
After=docker.service
ReloadPropagatedFrom=network.target docker.service

[Service]
Type=simple
Environment="WARP_HOME=<warphome>"
ExecStart=<warpctl> ....
ExecStop=/bin/kill -s TERM $MAINPID
TimeoutStopSec=0
Restart=always
StandardOutput=file:/var/log/warp/<service>-<block>.out
StandardError=file:/var/log/warp/<service>-<block>.err

[Install]
WantedBy=multi-user.target
Alias=redis.service
*/

// FIXME hardening
/*

ReadWriteDirectories=-/var/lib/redis
ReadWriteDirectories=-/var/log/redis
ReadWriteDirectories=-/run/redis

NoNewPrivileges=true
CapabilityBoundingSet=CAP_SETGID CAP_SETUID CAP_SYS_RESOURCE
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
MemoryDenyWriteExecute=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictNamespaces=true

ProtectSystem=true
ReadWriteDirectories=-/etc/redis
*/



    servicesUnits := map[string]map[string]string{}


    // generate lb
    lbUnits := map[string]string{}
    for block, blockInfo := range self.blockInfos["lb"] {
        parts := []string{}
        // parts = append(parts, fmt.Sprintf(`WARP_HOME="%s"`, self.targetWarpHome))

        parts = append(parts, []string{
            self.targetWarpctl,
            "service",
            "run",
            self.env,
            "lb",
            block,
        }...)

        routingTablesMap := map[int]bool{}
        if portBlocks, ok := self.portBlocks["lb"][block]; ok {
            for _, portBlock := range portBlocks {
                routingTablesMap[portBlock.routingTable] = true
            }
        }
        routingTables := maps.Keys(routingTablesMap)
        if 1 != len(routingTables) {
            panic("Each lb block must have one routing table.")
        }
        routingTable := routingTables[0]

        parts = append(parts, []string{
            fmt.Sprintf(`--rttable="%s:%d"`, blockInfo.interfaceName, routingTable),
            fmt.Sprintf("--dockernet=%s", blockInfo.lbBlock.DockerNetwork),
        }...)

        if portBlocks, ok := self.portBlocks["lb"][block]; ok {
            // add port block strs
            portBlockParts := []string{}
            for _, portBlock := range portBlocks {
                portBlockPart := fmt.Sprintf(
                    "%d:%d:%s",
                    portBlock.port,
                    portBlock.externalPort,
                    collapsePorts(portBlock.internalPorts),
                )
                portBlockParts = append(portBlockParts, portBlockPart)
            }
            part := fmt.Sprintf(`--portblocks="%s"`, strings.Join(portBlockParts, ";"))
            parts = append(parts, part)
        }

        parts = append(parts, fmt.Sprintf("--services_dockernet=%s", self.servicesConfig.Versions[0].ServicesDockerNetwork))

        vaultMode := "yes"
        configMode := "no"
        siteMode := "no"

        parts = append(parts, fmt.Sprintf("--mount_vault=%s", vaultMode))
        parts = append(parts, fmt.Sprintf("--mount_config=%s", configMode))
        parts = append(parts, fmt.Sprintf("--mount_site=%s", siteMode))

        lbUnits[block] = self.unit("lb", block, parts)
    }
    servicesUnits["lb"] = lbUnits

    // config-updater
    // enforce zero exposed ports for the config-updater
    configUpdaterUnits := map[string]string{}
    for block, _ := range self.blockInfos["config-updater"] {
        parts := []string{}
        // parts = append(parts, fmt.Sprintf(`WARP_HOME="%s"`, self.targetWarpHome))

        parts = append(parts, []string{
            self.targetWarpctl,
            "service",
            "run",
            self.env,
            "config-updater",
            block,
        }...)

        parts = append(parts, fmt.Sprintf("--services_dockernet=%s", self.servicesConfig.Versions[0].ServicesDockerNetwork))

        vaultMode := "no"
        configMode := "root"
        siteMode := "no"

        parts = append(parts, fmt.Sprintf("--mount_vault=%s", vaultMode))
        parts = append(parts, fmt.Sprintf("--mount_config=%s", configMode))
        parts = append(parts, fmt.Sprintf("--mount_site=%s", siteMode))

        configUpdaterUnits[block] = self.unit("config-updater", block, parts)
    }
    servicesUnits["config-updater"] = configUpdaterUnits


    for service, serviceBlockInfos := range self.blockInfos {
        switch service {
        case "lb", "config-updater":
            continue
        }

        serviceUnits := map[string]string{}
        for block, _ := range serviceBlockInfos {
            parts := []string{}
            // parts = append(parts, fmt.Sprintf(`WARP_HOME="%s"`, self.targetWarpHome))

            parts = append(parts, []string{
                self.targetWarpctl,
                "service",
                "run",
                self.env,
                service,
                block,
            }...)

            if portBlocks, ok := self.portBlocks[service][block]; ok {
                // add port block strs
                portBlockParts := []string{}
                for _, portBlock := range portBlocks {
                    portBlockPart := fmt.Sprintf(
                        "%d:%d:%s",
                        portBlock.port,
                        portBlock.externalPort,
                        collapsePorts(portBlock.internalPorts),
                    )
                    portBlockParts = append(portBlockParts, portBlockPart)
                }
                part := fmt.Sprintf("--portblocks=%s", strings.Join(portBlockParts, ";"))
                parts = append(parts, part)
            }

            parts = append(parts, fmt.Sprintf("--services_dockernet=%s", self.servicesConfig.Versions[0].ServicesDockerNetwork))

            vaultMode := "yes"
            configMode := "yes"
            siteMode := "yes"

            parts = append(parts, fmt.Sprintf("--mount_vault=%s", vaultMode))
            parts = append(parts, fmt.Sprintf("--mount_config=%s", configMode))
            parts = append(parts, fmt.Sprintf("--mount_site=%s", siteMode))

            serviceUnits[block] = self.unit(service, block, parts)
        }
        servicesUnits[service] = serviceUnits
    }

    return servicesUnits
}

func (self *SystemdUnits) unit(service string, block string, cmdArgs []string) string {

    unit := templateString(`
    [Unit]
    Description=Warpctl {{.env}}-{{.service}} block {{.block}}
    Requires=network.target
    After=network.target
    Requires=docker.service
    After=docker.service
    ReloadPropagatedFrom=network.target docker.service

    [Service]
    Type=simple
    Environment="WARP_HOME={{.warpHome}}"
    ExecStart={{.cmd}}
    ExecStop=/bin/kill -s TERM $MAINPID
    TimeoutStopSec=0
    Restart=always
    StandardOutput=file:/var/log/warp/{{.env}}-{{.service}}-{{.block}}.out
    StandardError=file:/var/log/warp/{{.env}}-{{.service}}-{{.block}}.err

    [Install]
    WantedBy=multi-user.target
    `, map[string]any{
        "env": self.env,
        "service": service,
        "block": block,
        "warpHome": self.targetWarpHome,
        "cmd": strings.Join(cmdArgs, " "),
    })

    return indentAndTrimString(unit, 0)
}



