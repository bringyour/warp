package main


import (

	"fmt"
    "os"
    "io"
    // "os/exec"
    "path"
    "encoding/json"
    "time"
    // "strings"
    // "math"
    "net"
    "net/http"
    "regexp"
    "context"
    "sync"
    "bytes"
    "strings"

    "golang.org/x/exp/maps"
	"golang.org/x/sync/semaphore"

    "github.com/coreos/go-semver/semver"
)


type WarpState struct {
    warpHome string
    warpVersionHome string
    warpSettings *WarpSettings
    versionSettings *VersionSettings
}


type WarpSettings struct {
    DockerNamespace *string `json:"dockerNamespace,omitempty"`
    DockerHubUsername *string `json:"dockerHubUsername,omitempty"`
    DockerHubToken *string `json:"dockerHubToken,omitempty"`
    VaultHome *string `json:"vaultHome,omitempty"`
    KeysHome *string `json:"keysHome,omitempty"`
    LbDomain *string `json:"lbDomain,omitempty"`
}


type VersionSettings struct {
    StagedVersion *string `json:"stagedVersion,omitempty"`
}


func getWarpState() *WarpState {
    warpHome := os.Getenv("WARP_HOME")
    if warpHome == "" {
        panic("WARP_HOME must be set.")
    }
    warpVersionHome := os.Getenv("WARP_VERSION_HOME")
    if warpVersionHome == "" {
        panic("WARP_VERSION_HOME must be set.")
    }

    var err error

    var warpSettings WarpSettings
    warpJson, err := os.ReadFile(path.Join(warpHome, "warp.json"))
    if err == nil {
        err = json.Unmarshal(warpJson, &warpSettings)
        if err != nil {
            panic(err)
        }
    }

    var versionSettings VersionSettings
    versionJson, err := os.ReadFile(path.Join(warpVersionHome, "version.json"))
    if err == nil {
        err = json.Unmarshal(versionJson, &versionSettings)
        if err != nil {
            panic(err)
        }
    }

    return &WarpState{
        warpHome: warpHome,
        warpVersionHome: warpVersionHome,
        warpSettings: &warpSettings,
        versionSettings: &versionSettings,
    }
}


func setWarpState(state *WarpState) {
    warpHome := os.Getenv("WARP_HOME")
    if warpHome == "" {
        panic("WARP_HOME must be set.")
    }
    warpVersionHome := os.Getenv("WARP_VERSION_HOME")
    if warpVersionHome == "" {
        panic("WARP_VERSION_HOME must be set.")
    }

    var err error

    warpJson, err := json.Marshal(state.warpSettings)
    if err != nil {
        panic(err)
    }
    err = os.WriteFile(path.Join(warpHome, "warp.json"), warpJson, os.FileMode(0770))
    if err != nil {
        panic(err)
    }

    versionJson, err := json.Marshal(state.versionSettings)
    if err != nil {
        panic(err)
    }
    err = os.WriteFile(path.Join(warpVersionHome, "version.json"), versionJson, os.FileMode(0770))
    if err != nil {
        panic(err)
    }
}


func getLocalVersion() string {
    host, err := os.Hostname()
    if err != nil {
        host = "nohost"
    }
    now := time.Now()
    year, month, day := now.Date()
    return fmt.Sprintf("%d.%d.%d-%s", year, month, day, host)
}


func getVersion(build bool, docker bool) string {
    state := getWarpState()

    stagedVersion := state.versionSettings.StagedVersion

    var version string
    if stagedVersion == nil || *stagedVersion == "local" {
        version = getLocalVersion()
    } else {
        version = *stagedVersion
    }

    if build {
        buildTimestamp := time.Now().UnixMilli()
        version = fmt.Sprintf("%s+%d", version, buildTimestamp)
    }

    if docker {
        version = convertVersionToDocker(version)
    }

    return version
}


type DockerHubLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type DockerHubLoginResponse struct {
	Token string `json:"token"`
}

type DockerHubReposResponse struct {
	NextUrl *string `json:"next"`
	Results []DockerHubReposResponseResult `json:"results"`
}

type DockerHubReposResponseResult struct {
	Name string `json:"name"`
	RepositoryType string `json:"repository_type"`
	StatusDescription string `json:"status_description"`
}

type DockerHubImagesResponse struct {
	NextUrl *string `json:"next"`
	Results []DockerHubImagesResponseResult `json:"results"`
}

type DockerHubImagesResponseResult struct {
	Tags []DockerHubImagesResponseResultTag `json:"tags"`
	Status string `json:"status"`
}

type DockerHubImagesResponseResultTag struct {
	Tag string `json:"tag"`
	IsCurrent bool `json:"is_current"`
}

type DockerHubClient struct {
	warpState *WarpState
	httpClient *http.Client
	token string
}

func NewDockerHubClient(warpState *WarpState) *DockerHubClient {
	state := getWarpState()

    if state.warpSettings.DockerHubUsername == nil {
    	panic("DockerHub username must be set.")
    }
    if state.warpSettings.DockerHubToken == nil {
    	panic("DockerHub username must be set.")
    }
    if state.warpSettings.DockerNamespace == nil {
    	panic("Docker namespace must be set.")
    }

	httpClient := &http.Client{}

    dockerHubLoginRequest := DockerHubLoginRequest{
    	Username: *state.warpSettings.DockerHubUsername,
    	Password: *state.warpSettings.DockerHubToken,
    }
    loginRequestJson, err := json.Marshal(dockerHubLoginRequest)
    if err != nil {
    	panic(err)
    }

    loginRequest, err := http.NewRequest(
    	"POST",
    	"https://hub.docker.com/v2/users/login",
    	bytes.NewReader(loginRequestJson),
    )
    if err != nil {
    	panic(err)
    }
    loginRequest.Header.Add("Content-Type", "application/json")
    loginResponse, err := httpClient.Do(loginRequest)
    if err != nil {
    	panic(err)
    }

    var dockerHubLoginResponse DockerHubLoginResponse
    body, err := io.ReadAll(loginResponse.Body)
    if err != nil {
    	panic(err)
    }
    err = json.Unmarshal(body, &dockerHubLoginResponse)
    if err != nil {
    	panic(err)
    }

    return &DockerHubClient{
    	warpState: state,
    	httpClient: httpClient,
    	token: dockerHubLoginResponse.Token,
    }
}

func (self *DockerHubClient) AddAuthorizationHeader(request *http.Request) {
	fmt.Printf("Authorization: Bearer %s\n", self.token)
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", self.token))
}

func (self *DockerHubClient) NamespaceUrl(path string) string {
	return fmt.Sprintf(
		"https://hub.docker.com/v2/namespaces/%s%s",
		*self.warpState.warpSettings.DockerNamespace,
		path,
	)
}


type ServiceMeta struct {
    envs []string
    services []string
    blocks []string
    envVersionMetas map[string]map[string]*VersionMeta
}


type VersionMeta struct {
    env string
    service string
    versions []*semver.Version
    latestBlocks map[string]*semver.Version
}


func getServiceMeta() *ServiceMeta {
	state := getWarpState()
    client := NewDockerHubClient(state)

    repoNames := []string{}

    url := client.NamespaceUrl("/repositories")
    for {
    	fmt.Printf("%s\n", url)
	    reposRequest, err := http.NewRequest("GET", url, nil)
	    if err != nil {
	    	panic(err)
	    }
	    client.AddAuthorizationHeader(reposRequest)

	    reposResponse, err := client.httpClient.Do(reposRequest)
	    if err != nil {
	    	panic(err)
	    }

	    var dockerHubReposResponse DockerHubReposResponse
	    body, err := io.ReadAll(reposResponse.Body)
	    if err != nil {
	    	panic(err)
	    }
	    err = json.Unmarshal(body, &dockerHubReposResponse)
	    if err != nil {
	    	panic(err)
	    }

		for _, result := range dockerHubReposResponse.Results {
			if result.RepositoryType == "image" && result.StatusDescription == "active" {
				repoNames = append(repoNames, result.Name)
			}
		}

		if dockerHubReposResponse.NextUrl == nil {
			break
		}
		url = *dockerHubReposResponse.NextUrl
	}

	envVersionMetas := map[string]map[string]*VersionMeta{}

	envsMap := map[string]bool{}
	servicesMap := map[string]bool{}
	blocksMap := map[string]bool{}
	
	// a service repo is named <env>-<service>
	repoRegex := regexp.MustCompile("^([^-]+)-(.+)$")
	for _, repoName := range repoNames {
		groups := repoRegex.FindStringSubmatch(repoName)
		if groups == nil {
			continue
		}

		env := groups[1]
		service := groups[2]

		versionMeta := getVersionMeta(env, service)

		if envVersionMetas[env] == nil {
			envVersionMetas[env] = map[string]*VersionMeta{}
		}
		envVersionMetas[env][service] = versionMeta

		envsMap[env] = true
		servicesMap[service] = true
		for block, _ := range versionMeta.latestBlocks {
			blocksMap[block] = true
		}
	}

	envs := maps.Keys(envsMap)
	services := maps.Keys(servicesMap)
	blocks := maps.Keys(blocksMap)

	return &ServiceMeta{
		envs: envs,
		services: services,
		blocks: blocks,
		envVersionMetas: envVersionMetas,
	}
}


func getVersionMeta(env string, service string) *VersionMeta {
	state := getWarpState()
    client := NewDockerHubClient(state)

	versionsMap := map[*semver.Version]bool{}
	latestBlocks := map[string]*semver.Version{}

	latestRegex := regexp.MustCompile("^(.*)-latest$")

	url := client.NamespaceUrl(fmt.Sprintf("/repositories/%s-%s/images", env, service))
	for {
	    imagesRequest, err := http.NewRequest("GET", url, nil)
	    if err != nil {
	    	panic(err)
	    }
	    client.AddAuthorizationHeader(imagesRequest)

	    imagesResponse, err := client.httpClient.Do(imagesRequest)
	    if err != nil {
	    	panic(err)
	    }
	    var dockerHubImagesResponse DockerHubImagesResponse
	    body, err := io.ReadAll(imagesResponse.Body)
	    if err != nil {
	    	panic(err)
	    }
	    err = json.Unmarshal(body, &dockerHubImagesResponse)
	    if err != nil {
	    	panic(err)
	    }

	    imageVersions := []*semver.Version{}
		for _, result := range dockerHubImagesResponse.Results {
			if result.Status == "active" {
				for _, tag := range result.Tags {
					if tag.IsCurrent {
						fmt.Printf("tag %s %t\n", tag.Tag, tag.IsCurrent)
						if version, err := semver.NewVersion(tag.Tag); err == nil {
							fmt.Printf("v %s %t\n", version, tag.IsCurrent)
							imageVersions = append(imageVersions, version)
							versionsMap[version] = true
						}
					}
				}
			}
		}
		for _, result := range dockerHubImagesResponse.Results {
			if result.Status == "active" {
				for _, tag := range result.Tags {
					if tag.IsCurrent {
						if groups := latestRegex.FindStringSubmatch(tag.Tag); groups != nil {
							block := groups[1]
							latestBlocks[block] = imageVersions[len(imageVersions) - 1]
						}
					}
				}
			}
		}

		if dockerHubImagesResponse.NextUrl == nil {
			break
		}
		url = *dockerHubImagesResponse.NextUrl
	}

	return &VersionMeta{
		env: env,
		service: service,
		versions: maps.Keys(versionsMap),
		latestBlocks: latestBlocks,
	}
}


func pollLbStatusUntil(env string, service string, sampleCount int, lbStatusUrls []string, targetVersion string) {
	for {
        statusVersions := sampleLbStatusVersions(20, lbStatusUrls)

        serviceCount := 0
        serviceVersions := []*semver.Version{}
        keysCount := 0
        keysVersions := []*semver.Version{}

        for version, count := range statusVersions.versions {
            serviceVersions = append(serviceVersions, version)
            serviceCount += count
        }
        for version, count := range statusVersions.keysVersions {
            keysVersions = append(keysVersions, version)
            keysCount += count
        }

        semver.Sort(serviceVersions)
        semver.Sort(keysVersions)

        if 0 < len(statusVersions.errors) {
            fmt.Printf("** errors **:\n")
            for errorMessage, count := range statusVersions.errors {
                fmt.Printf("    %s: %d\n", errorMessage, count)
            }
        }

        fmt.Printf("%s versions:\n", service)
        for _, version := range serviceVersions {
            count := statusVersions.versions[version]
            percent := 100.0 * count / serviceCount
            fmt.Printf("    %s: %d (%.1f%%)\n", version.String(), count, percent)
        }

        fmt.Printf("keys versions:\n")
        for _, version := range keysVersions {
            count := statusVersions.keysVersions[version]
            percent := 100.0 * count / keysCount
            fmt.Printf("    %s: %d (%.1f%%)\n", version.String(), count, percent)
        }

        if targetVersion == "" {
            break
        }
        if len(serviceVersions) == 1 && 
        		serviceVersions[0].String() == targetVersion && 
        		len(statusVersions.errors) == 0 {
            break
        }

        fmt.Printf("\n")

        time.Sleep(10 * time.Second)
    }
}


type StatusVersions struct {
	versions map[*semver.Version]int
	keysVersions map[*semver.Version]int
	errors map[string]int
}


type LbStatusResponse struct {
	Version string `json:"version"`
	KeysVersion string `json:"keysVersion"`
	Status string `json:"status"`
}


func sampleLbStatusVersions(sampleCount int, lbStatusUrls []string) *StatusVersions {
	// if status starts with error it is recorded as an error
	errorRegex := regexp.MustCompile("^(?i)error\\s")

	resultsMutex := sync.Mutex{}
	versions := map[*semver.Version]int{}
	keysVersions := map[*semver.Version]int{}
	errors := map[string]int{}

	addResults := func(lbStatusResponse *LbStatusResponse) {
		resultsMutex.Lock()
		defer resultsMutex.Unlock()

		version, err := semver.NewVersion(lbStatusResponse.Version)
		if err == nil {
			versions[version] += 1
		} else {
			errors["error status bad version"] += 1
		}

		keysVersion, err := semver.NewVersion(lbStatusResponse.KeysVersion)
		if err == nil {
			keysVersions[keysVersion] += 1
		} else {
			errors["error status bad keys version"] += 1
		}

		if errorRegex.MatchString(lbStatusResponse.Status) {
			errors[lbStatusResponse.Status] += 1
		}
	}

	sample := func(sem *semaphore.Weighted, lbStatusUrl string) {
		// do not use connection re-use or keep alives
		// each request should be a new connection
		httpClient := &http.Client{
	        Transport: &http.Transport{
	            DialContext: (&net.Dialer{
	                Timeout:   5 * time.Second,
	                KeepAlive: 5 * time.Second,
	            }).DialContext,
	            TLSHandshakeTimeout:   5 * time.Second,
	            ResponseHeaderTimeout: 5 * time.Second,
	            ExpectContinueTimeout: 1 * time.Second,
	            DisableKeepAlives: true,
	            MaxIdleConnsPerHost: -1,
	        },
	    }

	    sampleOne := func() *LbStatusResponse {
	    	statusRequest, err := http.NewRequest("GET", lbStatusUrl, nil)
			if err != nil {
				return &LbStatusResponse{
		    		Status: "error could not create request",
		    	}
			}
			statusResponse, err := httpClient.Do(statusRequest)
			if err != nil {
		    	return &LbStatusResponse{
		    		Status: "error status request failed",
		    	}
			}
			if statusResponse.StatusCode != 200 {
				return &LbStatusResponse{
		    		Status: fmt.Sprintf("error http status %d", statusResponse.StatusCode),
		    	}
			}

			var lbStatusResponse LbStatusResponse
			body, err := io.ReadAll(statusResponse.Body)
		    if err != nil {
		    	panic(err)
		    }
	    	err = json.Unmarshal(body, &lbStatusResponse)
	    	if err != nil {
	    		return &LbStatusResponse{
		    		Status: fmt.Sprintf("error could not parse status"),
		    	}
	    	}

			return &lbStatusResponse
	    }

		for i := 0; i < sampleCount; i += 1 {
			addResults(sampleOne())
		}
		sem.Release(1)
	}


	sem := semaphore.NewWeighted(0)
	for _, lbStatusUrl := range lbStatusUrls {
		go sample(sem, lbStatusUrl)
	}

	sem.Acquire(context.Background(), int64(len(lbStatusUrls)))

	return &StatusVersions{
		versions: versions,
		keysVersions: keysVersions,
		errors: errors,
	}
}


func pollBlockStatusUntil(env string, service string, blocks []string, targetVersion string) {
	state := getWarpState()

    blockStatusUrls := []string{}
    for _, block := range blocks {
    	// FIXME support private prefix also
        blockStatusUrl := fmt.Sprintf(
        	"%s-lb.%s/by/b/%s/%s/status",
        	env,
        	state.warpSettings.LbDomain,
        	service,
        	block,
        )
        blockStatusUrls = append(blockStatusUrls, blockStatusUrl)
    }

    pollLbStatusUntil(env, service, 20, blockStatusUrls, targetVersion)
}


func pollServiceStatusUntil(env string, service string, targetVersion string) {
	state := getWarpState()

	serviceStatusUrls := []string{
		// FIXME support private prefix also
		fmt.Sprintf(
			"%s-lb.%s/by/service/%s/status",
			env,
			state.warpSettings.LbDomain,
			service,
		),
	}

    pollLbStatusUntil(env, service, 20, serviceStatusUrls, targetVersion)
}


func listBlocks(env string, service string) []string {
	// FIXME parse the site definition and returns the blocks in order listed for the service
	return []string{}
}



func convertVersionToDocker(version string) string {
	// replace last + with -
	parts := strings.Split(version, "+")
	if 2 < len(parts) {
		panic("Bad semver: expecting at most one +")
	}
	return strings.Join(parts, "-")
}

func convertVersionFromDocker(dockerVersion string) string {
	// if two tailing -, replace last with + 
	parts := strings.Split(dockerVersion, "-")
	if 2 <= len(parts) {
		return fmt.Sprintf("%s+%s", strings.Join(parts[:len(parts) - 1], "-"), parts[len(parts) - 1])
	} else {
		return strings.Join(parts, "-")
	}
}

