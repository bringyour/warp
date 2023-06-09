package main

import (
    "fmt"
    "os"
    "os/exec"
    "path"
    // "encoding/json"
    "time"
    "strings"
    "math"
    "reflect"
    "sort"

    "golang.org/x/exp/maps"

    "github.com/docopt/docopt-go"
    "github.com/coreos/go-semver/semver"
)


const WARP_VERSION = "1.0.0"


// type CtlArgs struct {
//   InitDockerHubToken string `docopt:"--dockerhub_token"`
//   InitVaultHome string `docopt:"--vault_home"`
//   InitKeysHome int `docopt:"--keys_home"`
//   VersionNext string `docopt:"-next"`
//   VersionBeta string `docopt:"-beta"`
//   VersionRelease int `docopt:"-release"`
//   DeployPercent string `docopt:"--percent"`
//   CreateOutDir string `docopt:"--outdir"`
// }


// the vault is updated outside of warp using for example ansible
// the keys is updated with an updater service that writes new key versions into the key home
// fixme have a "latest" file that points to the latest keys version

// 1.2.3-beta+33234234


// WARP_HOME=/srv/warp
// WARP_VERSION_HOME

// warpctl lb run <env> <interface_name>
//  warpctl lb create-unit <env> <interface_name> [--target_warp_home=<target_warp_home>]
//  warpctl key-updater run <env>
//  warpctl key-updater create-unit <env>


// README
// docker containers run with /srv/warp/vault mounted read-only to the vault
// /srv/warp/keys mounted read-only to the keys

// lb does not have keys mounted

// the keys-updater service has /srv/warp/keys mounted read+write
// the keys-updater unit has no restart on exit

// all other units require keys-updater first
// lb requires all other units first


// build populates WARP_VAULT_HOME, WARP_KEYS_HOME, WARP_ENV and WARP_NAMESPACE



// all warp services should have a /status path with json: version, keys version, uptime




// needs a docker hub user access token
func main() {
    usage := `Warp control. Zero downtime continuous release.

The warp lifecycle is:
1. Stage a version
2. Build services
   This includes signing and pushing docker images.
3. Deploy services
   This includes tagging docker images in a repo as "latest".
4. Run services
   This includes watching for image attributes and starting new containers while draining old ones.
   Zero downtime means routing new connections to the new containers while the old ones drain.

Steps 1-3 happen on a developer or build machine. Step 4 happens on production machines in the target environment.

Usage:
    warpctl init
        [--docker_namespace=<docker_namespace>]
        [--dockerhub_username=<dockerhub_username>]
        [--dockerhub_token=<dockerhub_token>]
        [--vault_home=<vault_home>]
        [--keys_home=<keys_home>]
        [--lbdomain=<lbdomain>]
    warpctl stage version (local | sync | next (beta | release) --message=<message>)
    warpctl build <env> <Makefile>
    warpctl deploy <env> <service>
        (<version> | latest-local | latest-beta | latest)
        (<blocklist> | --percent=<percent>)
    warpctl deploy-local <env> <service> [--percent=<percent>]
    warpctl deploy-beta <env> <service> [--percent=<percent>]
    warpctl deploy-release <env> <service> [--percent=<percent>]
    warpctl ls version [-b] [-d]
    warpctl ls services [<env>]
    warpctl ls service-blocks [<env> [<service>]]
    warpctl ls versions [<env> [<service>]]
    warpctl lb create-config <env>
    warpctl service run <env> <service> <block> [<portblocks>] [<table>]
    warpctl service create-unit <env> <service> <block>
        [--target_warp_home=<target_warp_home>]
    warpctl create-units <env> --outdir=<outdir>
        [--target_warp_home=<target_warp_home>]

Options:
    -h --help                  Show this screen.
    --version                  Show version.
    --docker_namespace=<docker_namespace>      Your docker namespace. Docker repos are namespace/env-service.
    --dockerhub_username=<dockerhub_username>  Your dockerhub username.
    --dockerhub_token=<dockerhub_token>        Your dockerhub token.
    --vault_home=<vault_home>  Secure vault home (keys-red).
    --keys_home=<keys_home>    Keys home.
    --lbdomain=<lbdomain>      Load balancer domain. The lb is accessible at <env>-lb.<lbdomain>
    --message=<message>        Version stage message.
    --percent=<percent>        Deploy to a percent of blocks, ordered lexicographically with beta first.
                               The block count is rounded up to the nearest int. 
    -b                         Include the build timestamp in the version. Use this for builds.
    -d                         Docker safe version (converts + to -).
    --target_warp_home=<target_warp_home>  WARP_HOME for the unit.
    --outdir=<outdir>          Output dir.`

    opts, err := docopt.ParseArgs(usage, os.Args[1:], WARP_VERSION)
    if err != nil {
        panic(err)
    }

    if init_, _ := opts.Bool("init"); init_ {
        initWarp(opts)
    } else if stage, _ := opts.Bool("stage"); stage {
        if version, _ := opts.Bool("version"); version {
            stageVersion(opts)
        }
    } else if build_, _ := opts.Bool("build"); build_ {
        build(opts)
    } else if deploy_, _ := opts.Bool("deploy"); deploy_ {
        deploy(opts)
    } else if deployLocal_, _ := opts.Bool("deploy-local"); deployLocal_ {
        deployLocal(opts)
    } else if deployBeta_, _ := opts.Bool("deploy-beta"); deployBeta_ {
        deployBeta(opts)
    } else if deployRelease_, _ := opts.Bool("deploy-release"); deployRelease_ {
        deployRelease(opts)
    } else if ls, _ := opts.Bool("ls"); ls {
        if version, _ := opts.Bool("version"); version {
            lsVersion(opts)
        } else if services, _ := opts.Bool("services"); services {
            lsServices(opts)
        } else if serviceBlocks, _ := opts.Bool("serviceBlocks"); serviceBlocks {
            lsServiceBlocks(opts)
        } else if versions, _ := opts.Bool("versions"); versions {
            lsVersions(opts)
        }
    } else if lb, _ := opts.Bool("lb"); lb {
        if createConfig, _ := opts.Bool("create-config"); createConfig {
            lbCreateConfig(opts)
        }
    } else if service, _ := opts.Bool("service"); service {
        if run, _ := opts.Bool("run"); run {
            serviceRun(opts)
        } else if createUnit, _ := opts.Bool("create-unit"); createUnit {
            serviceCreateUnit(opts)
        }
    } else if createUnits_, _ := opts.Bool("create-units"); createUnits_ {
        createUnits(opts)
    }
}


func initWarp(opts docopt.Opts) {
    state := getWarpState()

    if dockerNamespace, err := opts.String("--docker_namespace"); err == nil {
        if dockerNamespace == "" {
            state.warpSettings.DockerNamespace = nil
        } else {
            state.warpSettings.DockerNamespace = &dockerNamespace
        }
    }
    if dockerHubUsername, err := opts.String("--dockerhub_username"); err == nil {
        if dockerHubUsername == "" {
            state.warpSettings.DockerHubUsername = nil
        } else {
            state.warpSettings.DockerHubUsername = &dockerHubUsername
        }
    }
    if dockerHubToken, err := opts.String("--dockerhub_token"); err == nil {
        if dockerHubToken == "" {
            state.warpSettings.DockerHubToken = nil
        } else {
            state.warpSettings.DockerHubToken = &dockerHubToken
        }
    }
    if vaultHome, err := opts.String("--vault_home"); err == nil {
        if vaultHome == "" {
            state.warpSettings.VaultHome = nil
        } else {
            state.warpSettings.VaultHome = &vaultHome
        }
    }
    if keysHome, err := opts.String("--keys_home"); err == nil {
        if keysHome == "" {
            state.warpSettings.KeysHome = nil
        } else {
            state.warpSettings.KeysHome = &keysHome
        }
    }
    if lbDomain, err := opts.String("--lbdomain"); err == nil {
        if lbDomain == "" {
            state.warpSettings.LbDomain = nil
        } else {
            state.warpSettings.LbDomain = &lbDomain
        }
    }
    
    setWarpState(state)
}


func stageVersion(opts docopt.Opts) {
    state := getWarpState()

    if local, _ := opts.Bool("local"); local {
        version := "local"
        state.versionSettings.StagedVersion = &version
        setWarpState(state)

        fmt.Printf("%s (local)\n", getVersion(false, false))
    } else {
        sync, _ := opts.Bool("sync")
        next, _ := opts.Bool("next")

        if sync || next {
            var err error

            gitStashCommand := exec.Command("git", "stash", "-u")
            gitStashCommand.Dir = state.warpVersionHome
            err = gitStashCommand.Run()
            if err != nil {
                panic(err)
            }

            gitPullCommand := exec.Command("git", "pull")
            gitPullCommand.Dir = state.warpVersionHome
            err = gitPullCommand.Run()
            if err != nil {
                panic(err)
            }
        }

        if next {
            var version string

            beta, _ := opts.Bool("beta")
            release, _ := opts.Bool("release")

            if state.versionSettings.StagedVersion == nil {
                now := time.Now()
                year, month, _ := now.Date()
                version = fmt.Sprintf("%d.%d.%d", year, month, 1)
            } else if *state.versionSettings.StagedVersion == "local" {
                panic("Local version detected after sync. Manually revert the version to the previously staged beta or release version.")
            } else {
                now := time.Now()
                year, month, _ := now.Date()
                stagedSemver := semver.New(*state.versionSettings.StagedVersion)
                if fmt.Sprintf("%d.%d", stagedSemver.Major, stagedSemver.Minor) == fmt.Sprintf("%d.%d", year, month) {
                    if stagedSemver.PreRelease == "beta" && release {
                        // moving from beta to release keeps the same patch
                        version = fmt.Sprintf("%d.%d.%d", year, month, stagedSemver.Patch)
                    } else {
                        version = fmt.Sprintf("%d.%d.%d", year, month, stagedSemver.Patch + 1)
                    }
                } else {
                    version = fmt.Sprintf("%d.%d.%d", year, month, 1)
                }
            }

            if beta {
                version = fmt.Sprintf("%s-beta", version)
            }

            state.versionSettings.StagedVersion = &version
            setWarpState(state)

            var err error

            gitAddCommand := exec.Command("git", "add", "version.json")
            gitAddCommand.Dir = state.warpVersionHome
            err = gitAddCommand.Run()
            if err != nil {
                panic(err)
            }

            message, _ := opts.String("--message")
            gitCommitCommand := exec.Command("git", "commit", "-m", message)
            gitCommitCommand.Dir = state.warpVersionHome
            err = gitCommitCommand.Run()
            if err != nil {
                panic(err)
            }

            gitPushCommand := exec.Command("git", "push")
            gitPushCommand.Dir = state.warpVersionHome
            err = gitPushCommand.Run()
            if err != nil {
                panic(err)
            }
        }

        fmt.Printf("%s\n", getVersion(false, false))
    }
}


func build(opts docopt.Opts) {
    // build env vars:
    // WARP_HOME (inherited)
    // WARP_VERSION_HOME (inherited)
    // WARP_VAULT_HOME
    // WARP_KEYS_HOME
    // WARP_NAMESPACE
    // WARP_VERSION
    // WARP_ENV

    makefile, _ := opts.String("<Makefile>")
    makefileName := path.Base(makefile)
    makfileDirPath := path.Dir(makefile)
    // the dir name is the service name
    service := path.Base(makfileDirPath)

    if makefileName != "Makefile" {
        panic("Makefile must point to file named Makefile")
    }

    state := getWarpState()

    if state.warpSettings.VaultHome == nil {
        panic("WARP_VAULT_HOME is not set. Use warpctl init.")
    }
    if state.warpSettings.KeysHome == nil {
        panic("WARP_KEYS_HOME is not set. Use warpctl init.")
    }
    if state.warpSettings.DockerNamespace == nil {
        panic("WARP_NAMESPACE is not set. Use warpctl init.")
    }

    env, _ := opts.String("<env>")

    version := getVersion(true, true)

    envVars := map[string]string{
        "WARP_VAULT_HOME": *state.warpSettings.VaultHome,
        "WARP_KEYS_HOME": *state.warpSettings.KeysHome,
        "WARP_NAMESPACE": *state.warpSettings.DockerNamespace,
        "WARP_VERSION": version,
        "WARP_ENV": env,
    }

    makeCommand := exec.Command("make")
    makeCommand.Dir = makfileDirPath
    for _, envPair := range os.Environ() {
        makeCommand.Env = append(makeCommand.Env, envPair)
    }
    for key, value := range envVars {
        makeCommand.Env = append(makeCommand.Env, fmt.Sprintf("%s=%s", key, value))
    }
    makeCommand.Stdin = os.Stdin
    makeCommand.Stdout = os.Stdout
    makeCommand.Stderr = os.Stderr

    err := makeCommand.Run()
    if err != nil {
        panic(err)
    }

    announceBuild(env, service, version)
}


func deploy(opts docopt.Opts) {
    state := getWarpState()

    env, _ := opts.String("<env>")
    service, _ := opts.String("<service>")

    var deployVersion string

    if version, err := opts.String("<service>"); err == nil {
        deployVersion = version
    } else {
        serviceMeta := getServiceMeta()
        versionMeta := serviceMeta.envVersionMetas[env][service]
        versions := versionMeta.versions

        filteredVersions := []*semver.Version{}

        if latestLocal, _ := opts.Bool("latest-local"); latestLocal {
            // keep only versions with pre release of this hostname
            hostname, err := os.Hostname()
            if err != nil {
                panic(err)
            }
            for _, version := range versions {
                if string(version.PreRelease) == hostname {
                    filteredVersions = append(filteredVersions, version)
                }
            }
        } else if latestBeta, _ := opts.Bool("latest-beta"); latestBeta {
            // keep only versions with pre release of beta
            for _, version := range versions {
                if version.PreRelease == "beta" {
                    filteredVersions = append(filteredVersions, version)
                }
            }
        } else if latest, _ := opts.Bool("latest"); latest {
            // keep only versions with no pre release
            for _, version := range versions {
                if version.PreRelease == "" {
                    filteredVersions = append(filteredVersions, version)
                }
            }
        } else {
            panic("Unknown filter.")
        }

        if len(filteredVersions) == 0 {
            panic("No matching versions.")
        }

        semver.Sort(filteredVersions)
        deployVersion = filteredVersions[len(filteredVersions) - 1].String()
    }

    fmt.Printf("Selected version %s\n", deployVersion)

    blocks := listBlocks(env, service)

    deployBlocks := []string{}

    if blocklist, err := opts.String("<blocklist>"); err == nil {
        blockmap := map[string]bool{}
        for _, block := range strings.Split(blocklist, ",") {
            blockmap[block] = true
        }
        for _, block := range blocks {
            if _, ok := blockmap[block]; ok {
                deployBlocks = append(deployBlocks, block)
            }
        }
    } else if percent, err := opts.Int("--percent"); err == nil {
        blockCount := int32(math.Ceil(float64(len(blocks) * percent) / 100.0))
        deployBlocks = append(deployBlocks, blocks[:blockCount]...)
    } else {
        panic("No matching blocks.")
    }

    if len(deployBlocks) == 0 {
        panic("No matching blocks.")
    }

    announceDeployStarted(env, service, deployBlocks, deployVersion)

    for _, block := range deployBlocks {
        // remove tag <block>-latest from current image
        // tag target image with <block>-latest

        sourceImageName := fmt.Sprintf(
            "%s/%s-%s:%s",
            state.warpSettings.DockerNamespace,
            env,
            service,
            convertVersionToDocker(deployVersion),
        )
        deployImageName := fmt.Sprintf(
            "%s/%s-%s:%s-latest",
            state.warpSettings.DockerNamespace,
            env,
            service,
            block,
        )

        var err error

        dockerRmiCommand := exec.Command("docker", "rmi", deployImageName)
        dockerRmiCommand.Dir = state.warpVersionHome
        err = dockerRmiCommand.Run()
        if err != nil {
            panic(err)
        }

        dockerTagCommand := exec.Command("docker", "tag", sourceImageName, deployImageName)
        dockerTagCommand.Dir = state.warpVersionHome
        err = dockerTagCommand.Run()
        if err != nil {
            panic(err)
        }

        dockerPushCommand := exec.Command("docker", "push", deployImageName)
        dockerPushCommand.Dir = state.warpVersionHome
        err = dockerPushCommand.Run()
        if err != nil {
            panic(err)
        }

        fmt.Printf("Deployed %s -> %s\n", sourceImageName, deployImageName)
    }

    // poll the load balancer for the specific blocks until the versions stabilize
    pollBlockStatusUntil(env, service, deployBlocks, deployVersion)

    if reflect.DeepEqual(blocks, deployBlocks) {
        // poll the load balancer for all blocks until the version stabilizes
        pollServiceStatusUntil(env, service, deployVersion)
    }

    announceDeployEnded(env, service, deployBlocks, deployVersion)
}


func deployLocal(opts docopt.Opts) {
    opts["latest-local"] = true
    deploy(opts)
}

func deployBeta(opts docopt.Opts) {
    opts["latest-beta"] = true
    deploy(opts)
}

func deployRelease(opts docopt.Opts) {
    opts["latest"] = true
    deploy(opts)
}

func lsVersion(opts docopt.Opts) {
    build, _ := opts.Bool("-b")
    docker, _ := opts.Bool("-d")
    version := getVersion(build, docker)
    fmt.Printf("%s\n", version)
}


func lsServices(opts docopt.Opts) {
    filterEnv, filterEnvErr := opts.String("<env>")
    includeEnv := func(env string) bool {
        return filterEnvErr != nil || filterEnv == env
    }

    serviceMeta := getServiceMeta()

    sort.Strings(serviceMeta.envs)
    sort.Strings(serviceMeta.services)

    for _, env := range serviceMeta.envs {
        if !includeEnv(env) {
            continue
        }
        for _, service := range serviceMeta.services {
            // FIXME limit the blocks to only blocks inside this list, and print blocks in this order
            // blocks := listBlocks(env, service)

            if versionMeta, ok := serviceMeta.envVersionMetas[env][service]; ok {
                count := 0
                versionCounts := map[*semver.Version]int{}
                for _, version := range versionMeta.latestBlocks {
                    count += 1
                    versionCounts[version] += 1
                }
                versions := maps.Keys(versionCounts)
                semver.Sort(versions)
                histoParts := []string{}
                for _, version := range versions {
                    versionCount := versionCounts[version]
                    histoPart := fmt.Sprintf("%.1f %s", 100.0 * versionCount / count, version.String())
                    histoParts = append(histoParts, histoPart)
                }

                blockParts := []string{}
                if len(versionMeta.latestBlocks) == 0 {
                    blockParts = append(blockParts, "no deployed blocks")
                } else {
                    for block, version := range versionMeta.latestBlocks {
                        blockParts = append(blockParts, fmt.Sprintf("%s=%s", block, version.String()))
                    }
                }

                fmt.Printf("%s-%s (%s: %s)\n", env, service, strings.Join(histoParts, " "), strings.Join(blockParts, " "))
            }
        }
    }
}


func lsServiceBlocks(opts docopt.Opts) {
    filterEnv, filterEnvErr := opts.String("<env>")
    includeEnv := func(env string) bool {
        return filterEnvErr != nil || filterEnv == env
    }

    filterService, filterServiceErr := opts.String("<service>")
    includeService := func(service string) bool {
        return filterServiceErr != nil || filterService == service
    }

    serviceMeta := getServiceMeta()

    sort.Strings(serviceMeta.envs)
    sort.Strings(serviceMeta.services)
    sort.Strings(serviceMeta.blocks)

    for _, env := range serviceMeta.envs {
        if !includeEnv(env) {
            continue
        }
        for _, service := range serviceMeta.services {
            if !includeService(service) {
                continue
            }
            if versionMeta, ok := serviceMeta.envVersionMetas[env][service]; ok {
                for _, block := range serviceMeta.blocks {
                    if blockVersion, ok := versionMeta.latestBlocks[block]; ok {
                        fmt.Printf("%s-%s %s %s\n", env, service, block, blockVersion.String())
                    }
                }
            }
        }
    }
}


func lsVersions(opts docopt.Opts) {
    filterEnv, filterEnvErr := opts.String("<env>")
    includeEnv := func(env string) bool {
        return filterEnvErr != nil || filterEnv == env
    }

    filterService, filterServiceErr := opts.String("<service>")
    includeService := func(service string) bool {
        return filterServiceErr != nil || filterService == service
    }

    serviceMeta := getServiceMeta()

    sort.Strings(serviceMeta.envs)
    sort.Strings(serviceMeta.services)

    for _, env := range serviceMeta.envs {
        if !includeEnv(env) {
            continue
        }
        for _, service := range serviceMeta.services {
            if !includeService(service) {
                continue
            }
            if versionMeta, ok := serviceMeta.envVersionMetas[env][service]; ok {                
                // summarize per base (MAJOR, MINOR, R) in MAJOR.MINOR.[p-P,p,p-P]-R+COUNT range format

                semver.Sort(versionMeta.versions)

                baseVersionsMap := map[*semver.Version][]*semver.Version{}
                for _, version := range versionMeta.versions {
                    baseVersion := semver.New(fmt.Sprintf("%d.%d.0-%s", version.Major, version.Minor, version.PreRelease))
                    baseVersionsMap[baseVersion] = append(baseVersionsMap[baseVersion], version)
                }
                baseVersions := maps.Keys(baseVersionsMap)
                semver.Sort(baseVersions)
                for _, baseVersion := range baseVersions {
                    versions := baseVersionsMap[baseVersion]
                    semver.Sort(versions)
                    patchParts := []string{}
                    for i := 0; i < len(versions); {
                        j := i + 1
                        for ; j < len(versions); j += 1 {
                            if versions[j - 1].Patch  != versions[j].Patch - 1 {
                                break
                            }
                        }
                        var patchPart string
                        if i == j - 1 {
                            // single
                            patchPart = fmt.Sprintf("%d", versions[i].Patch)
                        } else {
                            // range
                            patchPart = fmt.Sprintf("%d-%d", versions[i].Patch, versions[j - 1].Patch)
                        }
                        patchParts = append(patchParts, patchPart)
                        i = j
                    }

                    if baseVersion.PreRelease == "" {
                        fmt.Printf(
                            "%s-%s %d.%d.[%s]+%d\n",
                            env,
                            service,
                            baseVersion.Major,
                            baseVersion.Minor,
                            strings.Join(patchParts, ","),
                            len(versions),
                        )
                    } else {
                        fmt.Printf(
                            "%s-%s %d.%d.[%s]-%s+%d\n",
                            env,
                            service,
                            baseVersion.Major,
                            baseVersion.Minor,
                            strings.Join(patchParts, ","),
                            baseVersion.PreRelease,
                            len(versions),
                        )
                    }
                }
            }
        }
    }
}


// FIXME lb can have one or more secret prefixes in the site config
// FIXME these will be at the start of the routes, so that only clients that know the secret can access the route
func lbCreateConfig(opts docopt.Opts) {
    // FIXME read the site meta data
    fmt.Printf("nginx config\n")

    // FIXME lb.go
}


func serviceRun(opts docopt.Opts) {
    // must have root permissions
    // for lb, set up route table; set up lb network; add lb network to service network
    // 

    // FIXME run.go
}

    
func serviceCreateUnit(opts docopt.Opts) {
    // for lb, get the routing table from the config file

    // FIXME unit.go
}


func createUnits(opts docopt.Opts) {
    // FIXME unit.go
}





