package main

import (
	"golang.org/x/exp/slices"
)


type ServicesConfig struct {
	Domain string
	CorsHost string
	HiddenPrefixes []string
	LbHiddenPrefixes []string
	versions []*ServiceConfigVersion


}



func (self *ServicesConfig) services() map[string]*ServiceConfig {
	return self.versions[0].Services
}



type ServiceConfigVersion struct {
	ExternalPorts string
	InternalPorts string
	ParallelBlockCount int
	ServicesDockerNetwork string

	Lb *LbConfig
	Services map[string]*ServiceConfig
}

type LbConfig struct {
	Ports []string
	Interfaces map[string]map[string]*LbBlockInfo
}


type ServiceConfig struct {
	ExposeAliases []string
	Exposed bool
	LbExposed bool
	Hosts []string
	Ports string
	Blocks []map[string]int
}

func (self *ServiceConfig) IncludesHost(host string) bool {
	return len(self.Hosts) == 0 || slices.Contains(self.Hosts, host)
}



type LbBlockInfo struct {
	DockerNetwork string
	ConcurrentClients int
	Cores int
}





// load from the vaulthome
func getServicesConfig(env string) *ServicesConfig {

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

	services := maps.Keys(self.serviceConfig.services)
	strings.Sort(services)
	
	for _, service := range services {
		if !serviceConfig.services[service].Exposed {
			continue
		}

		serviceHost := fmt.Sprintf("%s-%s.%s", env, service, domain)
		hosts = append(hosts, serviceHost)

		for _, serviceHostAlias := range self.serviceConfig.services[service].ExposeAliases {
			hosts = append(hosts, serviceHostAlias)
		}
	}

	return hosts
}


func getHiddenPrefix(env string) string {
	servicesConfig := getServicesConfig(env)
	if 0 < len(servicesConfig.hiddenPrefixes) {
		return servicesConfig.hiddenPrefixes[0]
	}
	return ""
}


func getLbHiddenPrefix(env string) string {
	servicesConfig := getServicesConfig(env)
	if 0 < len(servicesConfig.lbHiddenPrefixes) {
		return servicesConfig.lbHiddenPrefixes[0]
	}
	if 0 < len(servicesConfig.hiddenPrefixes) {
		return servicesConfig.hiddenPrefixes[0]
	}
	return ""
}


func IsExposed(env string, service string) bool {
	servicesConfig := getServicesConfig(env)
	return servicesConfig.services[service].Exposed
}


func IsLbExposed(env string, service string) bool {
	servicesConfig := getServicesConfig(env)
	return servicesConfig.services[service].LbExposed
}



const (
	BLOCK_TYPE_LB = "lb"
	BLOCK_TYPE_SERVICE = "service"
)


// union lb and service blocks
type BlockInfo struct {
	blockType string
	name string
	weight int

	host string
	interfaceName string
	lbBlockInfo *LbBlockInfo

	serviceBlockInfo *ServiceBlockInfo
}



// service -> blockinfo
func getBlockInfos(env string) map[string][]*BlockInfo {
	// FIXME parse the site definition and returns the blocks in order listed for the service
	return []string{}
}

func getBlocks(env string, service string) []string {
	blockInfos := getBlockInfos(env)
	blocks := maps.Keys(blockInfos[service])
	return blocks
}




type PortBlock struct {

}


// service -> block -> port block
// port block is external port:service port:internal port range
func getPortBlocks(env string) map[string]map[string]*PortBlock {
	
}








type NginxConfig struct {
	env string
	envAliases []string
	servicesConfig *ServicesConfig
	portBlocks map[string]map[string]*PortBlock
	blockInfos map[string]map[string]*BlockInfo
	// services []string

	relativeTlsPemPath string
	relativeTlsKeyPath string

	// lbBlockHost string
	// lbBlockInterface string
	lbBlockInfo *BlockInfo
	configParts []string
}

func NewNginxConfig(env string, envAliases []string) *NginxConfig {
	state := getWarpState()

	servicesConfig := getServicesConfig(env)

	// resolve the wildcard tls
	// <vault>/tls/<maxversion>/star_<domain>/star_<domain>.pem
	// <vault>/tls/<maxversion>/star_<domain>/star_<domain>.key
	// FIXME

	// services := maps.Keys(self.serviceConfig.services)
	// strings.Sort(services)

	return &NginxConfig{
		servicesConfig: servicesConfig,
		portBlocks: getPortBlocks(env),
		blockInfos: getBlockInfos(env),
		services: services,
		tlsPemPath: tlsPemPath,
		tlsKeyPath: tlsKeyPath
	}
}


func (self *NginxConfig) services() []string {
	// filter services based on which ones are exposed to the lbBlockInfo.host

	services := []string{}
	for service, serviceConfig := range self.servicesConfig.services() {
		if serviceConfig.IncludesHost(self.lbBlockHost) {
			services = append(services, service)
		}
	}
	strings.Sort(services)
	return services
}


func (self *NginxConfig) raw(text string, data map[string]interface{}...) {
	configPart := templateString(text, data...)
	self.configParts = append(self.configParts, configPart)
}

func (self *NginxConfig) cblock(tag string, body func()) {
	open := fmt.Sprintf("%s {", tag)
	close := "}"
	self.configParts = append(self.configParts, open)
	body()
	self.configParts = append(self.configParts, close)
}

// lb block -> config
func (self *NginxConfig) generate() map[string]string {
	blockConfigs := map[string]string{}

	for block, blockInfo := range self.blockInfos["lb"] {
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

	self.raw(`
	# target concurrent users (from services.yml): {{.concurrentCount}}
	# https://www.nginx.com/blog/tuning-nginx/
	worker_processes {{.coreCount}};
	events {
	    worker_connections {{.workersPerCore}};
	    multi_accept on;
	}
	`, map[string]interface{}{
		concurrentCount: concurrentCount,
		coreCount: coreCount,
		workersPerCore: workersPerCore,
	})

	self.cblock("http", func(){
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

		self.raw(`
	    server {
	        listen 80 default_server;
	        server_name _;

	        location / {
	            deny all;
	        }
	    }
		`)

		self.addLbBlock()

		self.addServiceBlocks()
	})
}



func (self *NginxConfig) addUpstreamBlocks() {
	// service-block-<service>
	// service-block-<service>-<block>
	for _, service := range self.services() {
		blocks := maps.Keys(portBlocks[service])
		strings.Sort(blocks)

		upstreamServers := []string{}
		for _, block := range blocks {
			portBlock, ok := portBlocks[service][block]
			if !ok {
				panic()
			}
			blockInfo, ok := blockInfos[service][block]
			if !ok {
				panic()
			}

			upstreamServer := templateString("server {{.dockerNetwork}}:{{.externalPort}} weight={{.weight}};",
				map[string]interface{}{
					"dockerNetwork": servicesConfig.servicesDockerNetwork,
					"externalPort": portBlock.externalPort,
					"weight": blockInfo.weight,
				}
			)
			upstreamServers = append(upstreamServers, upstreamServer)
		}

		self.raw(`
		upstream service-block-{{.service}} {
			{{.upstreamServers}}

			keepalive 1024;
		    keepalive_requests 1024;
		    keepalive_time 30s;
		    keepalive_timeout 30s;
		}
		`, map[string]interface{}{
			"service": service,
			"upstreamServers": strings.Join(upstreamServers, "\n"),
		})

		for _, block := range blocks {
			portBlock, ok := portBlocks[service][block]
			if !ok {
				panic()
			}

			self.raw(`
			upstream service-block-{{.service}}-{{.block}} {
				server {{.dockerNetwork}}:{{.externalPort}};

				keepalive 1024;
			    keepalive_requests 1024;
			    keepalive_time 30s;
			    keepalive_timeout 30s;
			}
			`, map[string]interface{}{
				"service": service,
				"block": block,
				"dockerNetwork": servicesConfig.servicesDockerNetwork,
				"externalPort": portBlock.externalPort,
			})
		}
	}
}



func (self *NginxConfig) addLbBlock() {
	var rootPrefix string
	lbHiddenPrefix = getLbHiddenPrefix(env)
	if lbHiddenPrefix == "" {
		rootPrefix = ""
	} else {
		rootPrefix = fmt.Sprintf("/%s", lbHiddenPrefix)
	}

	// /by/service/{service}/
    // /by/b/{service}/{name}/
	locations := []string{}

	for _, service := range self.services() {
		if !serviceConfig.services[service].LbExposed {
			continue
		}

		blocks := maps.Keys(portBlocks[service])
		strings.Sort(blocks)

		serviceHost := fmt.Sprintf("%s-%s.%s", self.env, service, domain)

		serviceLocation := templateString(`
		location {{.rootPrefix}}/by/service/%s/ {
            limit_req zone=standardlimit burst=50 delay=25;
            proxy_pass http://service-block-{{.service}}/;
            proxy_set_header X-Forwarded-For $remote_addr;
            proxy_set_header Host {{.serviceHost}};
        }
		`, map[string]interface{}{
			"rootPrefix": rootPrefix,
			"service": service,
			"serviceHost": serviceHost,
		})
		locations = append(locations, serviceLocation)

		for _, block := range blocks {
			serviceBlockLocation := templateString(`
			location {{.rootPrefix}}/by/b/{{.service}}/{{.block}}/ {
	            limit_req zone=standardlimit burst=50 delay=25;
	            proxy_pass http://service-block-{{.service}}-{{.block}}/;
	            proxy_set_header X-Forwarded-For $remote_addr;
	            proxy_set_header Host {{.serviceHost}};
	        }
			`, map[string]interface{}{
				"rootPrefix", rootPrefix,
				"service": service,
				"block": block,
				"serviceHost": serviceHost,
			})
			locations = append(locations, serviceBlockLocation)
		}
	}

	lbHosts := []string{}

	lbHost := fmt.Sprintf("%s-lb.%s", self.env, domain)
	lbHosts = append(lbHosts, lbHost)

	for _, env := self.envAliases {
		lbHostAlias := fmt.Sprintf("%s-lb.%s", env, domain)
		lbHosts = append(lbHosts, lbHostAlias)
	}

	self.raw(`
	server {
        listen 80;
        server_name {{.lbHostList}};
        return 301 https://$host$request_uri;
    }
	server {
        listen 443 ssl;
        server_name {{.lbHostList}};
        ssl_certificate     /srv/warp/vault/{{.relativeTlsPemPath}};
        ssl_certificate_key /srv/warp/vault/{{.relativeTlsKeyPath}};

        {{.locations}}
    }
	`, map[string]interface{}{
		"lbHostList": strings.Join(lbHosts, " "),
		"relativeTlsPemPath": self.relativeTlsPemPath,
		"relativeTlsKeyPath": self.relativeTlsKeyPath,
		"locations": strings.Join(locations, "\n"),
	})
}

func (self *NginxConfig) addServiceBlocks() {
	var rootPrefix string
	hiddenPrefix := getHiddenPrefix(env)
	if hiddenPrefix == "" {
		rootPrefix = ""
	} else {
		rootPrefix = fmt.Sprintf("/%s", hiddenPrefix)
	}

	for _, service := range self.services() {
		if !serviceConfig.services[service].Exposed {
			continue
		}

		serviceHosts := []string{}

		serviceHost := fmt.Sprintf("%s-%s.%s", self.env, service, domain)
		serviceHosts = append(serviceHosts, serviceHost)

		for _, env := range self.envAliases {
			serviceHostAlias := fmt.Sprintf("%s-%s.%s", env, service, domain)
			serviceHosts = append(serviceHosts, serviceHostAlias)
		}

		for _, serviceHostAlias := range self.serviceConfig.services[service].ExposeAliases {
			serviceHosts = append(serviceHosts, serviceHostAlias)
		}

		self.raw(`
	    server {
	        listen 80;
	        server_name {{.serviceHostList}};
	        return 301 https://$host$request_uri;
	    }
	    server {
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
	    }
		`, map[string]interface{}{
			"serviceHostList": strings.Join(serviceHosts, " "),
			"relativeTlsPemPath": self.relativeTlsPemPath,
			"relativeTlsKeyPath": self.relativeTlsKeyPath,
			"rootPrefix": rootPrefix,
			"service", service,
			"corsHost", self.servicesConfig.corsHost,
		})
	}
}

