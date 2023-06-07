package main

import (
    "fmt"
    "os"
    "os/exec"
    "path"
    "encoding/json"
    "time"

    "github.com/docopt/docopt-go"
    "github.com/coreos/go-semver/semver"
)


const WARP_VERSION = "1.0.0"


type CtlArgs struct {
  InitDockerhubToken string `docopt:"--dockerhub_token"`
  InitVaultHome string `docopt:"--vault_home"`
  InitKeysHome int `docopt:"--keys_home"`
  VersionNext string `docopt:"-next"`
  VersionBeta string `docopt:"-beta"`
  VersionRelease int `docopt:"-release"`
  DeployPercent string `docopt:"--percent"`
  CreateOutDir string `docopt:"--outdir"`
}


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


// build populates WARP_VAULT_HOME, WARP_KEYS_HOME, WARP_ENV and WARP_REPO



// all warp services should have a /status path with json: version, keys version, uptime




// needs a docker hub user access token
func main() {
    usage := `Warp control. Zero downtime continuous release.

The warp lifecycle is:
1. Stage a version
2. Build services
   This includes signing and publishing docker images to repo.
3. Deploy services
   This includes tagging docker images in a repo as "latest".
4. Run services
   This includes watching for image attributes and starting new containers while draining old ones.
   Zero downtime means routing new connections to the new containers while the old ones drain.

Steps 1-3 happen on a developer or build machine. Step 4 happens on production machines in the target environment.

Usage:
    warpctl init
        [--docker_repo_name=<docker_repo_name>]
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
    warpctl ls services
    warpctl ls service-blocks [<service>]
    warpctl ls versions [<service>]
    warpctl lb create-config <env>
    warpctl service run <env> <service> <block> [<portblocks>] [<table>]
    warpctl service create-unit <env> <service> <block>
        [--target_warp_home=<target_warp_home>]
    warpctl create-units <env> --outdir=<outdir>
        [--target_warp_home=<target_warp_home>]

Options:
    -h --help                  Show this screen.
    --version                  Show version.
    --docker_repo_name=<docker_repo_name>  Your docker repo name.
    --dockerhub_token=<dockerhub_token>    Your dockerhub token.
    --vault_home=<vault_home>  Secure vault home (keys-red).
    --keys_home=<keys_home>    Keys home.
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

    args := CtlArgs{}
    opts.Bind(&args)

    if init_, _ := opts.Bool("init"); init_ {
        initWarp(opts, args)
    } else if stage, _ := opts.Bool("stage"); stage {
        if version, _ := opts.Bool("version"); version {
            stageVersion(opts, args)
        }
    } else if build_, _ := opts.Bool("build"); build_ {
        build(opts, args)
    } else if deploy_, _ := opts.Bool("deploy"); deploy_ {
        deploy(opts, args)
    } else if deployLocal_, _ := opts.Bool("deploy-local"); deployLocal_ {
        deployLocal(opts, args)
    } else if deployBeta_, _ := opts.Bool("deploy-beta"); deployBeta_ {
        deployBeta(opts, args)
    } else if deployRelease_, _ := opts.Bool("deploy-release"); deployRelease_ {
        deployRelease(opts, args)
    } else if ls, _ := opts.Bool("ls"); ls {
        if version, _ := opts.Bool("version"); version {
            lsVersion(opts, args)
        } else if services, _ := opts.Bool("services"); services {
            lsServices(opts, args)
        } else if serviceBlocks, _ := opts.Bool("serviceBlocks"); serviceBlocks {
            lsServiceBlocks(opts, args)
        } else if versions, _ := opts.Bool("versions"); versions {
            lsVersions(opts, args)
        }
    } else if lb, _ := opts.Bool("lb"); lb {
        if createConfig, _ := opts.Bool("create-config"); createConfig {
            lbCreateConfig(opts, args)
        }
    } else if service, _ := opts.Bool("service"); service {
        if run, _ := opts.Bool("run"); run {
            serviceRun(opts, args)
        } else if createUnit, _ := opts.Bool("create-unit"); createUnit {
            serviceCreateUnit(opts, args)
        }
    } else if createUnits_, _ := opts.Bool("create-units"); createUnits_ {
        createUnits(opts, args)
    }
}


type WarpState struct {
    warpHome string
    warpVersionHome string
    warpSettings *WarpSettings
    versionSettings *VersionSettings
}


type WarpSettings struct {
    DockerRepoName *string `json:"dockerRepoName,omitempty"`
    DockerHubToken *string `json:"dockerHubToken,omitempty"`
    VaultHome *string `json:"vaultHome,omitempty"`
    KeysHome *string `json:"keysHome,omitempty"`
}


type VersionSettings struct {
    StagedVersion *string `json:"stagedVersion,omitempty"`
}


func GetWarpState() *WarpState {
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


func SetWarpState(state *WarpState) {
  // FIXME write the files

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
    return fmt.Sprintf("%04d.%02d.%02d-%s", year, month, day, host)
}


func getVersion(build bool, docker bool) string {
    state := GetWarpState()

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


// FIXME serviceStatusUntil


func blockStatusUntil(env, service, blocks []string, targetVersion string) {
    // sample the service block status from the outside to test the real routing

    blockStatusUrls := []string{}
    for _, block := range blocks {
        blockStatusUrl = fmt.Sprintf("%s-lb.%s/by/b/%s/%s/status", env, domain, service, block)
        blockStatusUrls = append(blockStatusUrls, blockStatusUrl)
    }

    for {
        statusVersions := sampleStatusVersions(20, blockStatusUrls)

        serviceCount := 0
        serviceVersions := []*semver.Version
        keysCount := 0
        keysVersions := []*semver.Version

        for version, count := range statusVersions.service {
            serviceVersions = append(serviceVersions, version)
            serviceCount += count
        }
        for version, count := range statusVersions.keys {
            keysVersions = append(keysVersions, version)
            keysCount += count
        }

        semver.Sort(serviceVersions)
        semver.Sort(keysVersions)

        if 0 < len(statusVersions.errors) {
            fmt.Printf("** errors **:\n")
            for errorCode, count := range statusVersions.errors {
                fmt.Printf("    %d: %d\n", errorCode, count)
            }
        }

        fmt.Printf("%s versions:\n", service)
        for _, version := range serviceVersions {
            count := statusVersions.service[version]
            percent := 100.0 * count / serviceCount
            fmt.Printf("    %s: %d (%.1f%%)\n", version.String(), count, percent)
        }

        fmt.Printf("keys versions:\n")
        for _, version := range keysVersions {
            count := statusVersions.keys[version]
            percent := 100.0 * count / keysCount
            fmt.Printf("    %s: %d (%.1f%%)\n", version.String(), count, percent)
        }

        if targetVersion == "" {
            break
        }
        if len(serviceVersions) == 1 && serviceVersions[0] == targetVersion {
            break
        }

        fmt.Printf("\n")

        time.Sleep(10 * time.Second)
    }
}




func initWarp(opts docopt.Opts, args CtlArgs) {
    state := GetWarpState()

    if dockerRepoName, err := opts.String("--docker_repo_name"); err == nil {
        state.warpSettings.DockerRepoName = &dockerRepoName
    }
    if dockerHubToken, err := opts.String("--dockerhub_token"); err == nil {
        state.warpSettings.DockerHubToken = &dockerHubToken
    }
    if vaultHome, err := opts.String("--vault_home"); err == nil {
        state.warpSettings.VaultHome = &vaultHome
    }
    if keysHome, err := opts.String("--keys_home"); err == nil {
        state.warpSettings.KeysHome = &keysHome
    }
    
    SetWarpState(state)
}


func stageVersion(opts docopt.Opts, args CtlArgs) {
    state := GetWarpState()

    if local, _ := opts.Bool("local"); local {
        version := "local"
        state.versionSettings.StagedVersion = &version
        SetWarpState(state)

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
                version = fmt.Sprintf("%04d.%02d.%d", year, month, 1)
            } else if *state.versionSettings.StagedVersion == "local" {
                panic("Local version detected after sync. Manually revert the version to the previously staged beta or release version.")
            } else {
                now := time.Now()
                year, month, _ := now.Date()
                stagedSemver := semver.New(*state.versionSettings.StagedVersion)
                if fmt.Sprintf("%04d.%02d", stagedSemver.Major, stagedSemver.Minor) == fmt.Sprintf("%04d.%02d", year, month) {
                    if stagedSemver.PreRelease == "beta" && release {
                        // moving from beta to release keeps the same patch
                        version = fmt.Sprintf("%04d.%02d.%d", year, month, stagedSemver.Patch)
                    } else {
                        version = fmt.Sprintf("%04d.%02d.%d", year, month, stagedSemver.Patch + 1)
                    }
                } else {
                    version = fmt.Sprintf("%04d.%02d.%d", year, month, 1)
                }
            }

            if beta {
                version = fmt.Sprintf("%s-beta", version)
            }

            state.versionSettings.StagedVersion = &version
            SetWarpState(state)

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


func build(opts docopt.Opts, args CtlArgs) {
    // build env vars:
    // WARP_HOME (inherited)
    // WARP_VERSION_HOME (inherited)
    // WARP_VAULT_HOME
    // WARP_KEYS_HOME
    // WARP_REPO
    // WARP_VERSION
    // WARP_ENV

    makefile, _ := opts.String("<Makefile>")
    makefileName := path.Base(makefile)
    makfileDir := path.Dir(makefile)

    if makefileName != "Makefile" {
        panic("Makefile must point to file named Makefile")
    }

    state := GetWarpState()

    if state.warpSettings.VaultHome == nil {
        panic("WARP_VAULT_HOME is not set. Use warpctl init.")
    }
    if state.warpSettings.KeysHome == nil {
        panic("WARP_KEYS_HOME is not set. Use warpctl init.")
    }
    if state.warpSettings.DockerRepoName == nil {
        panic("WARP_REPO is not set. Use warpctl init.")
    }

    env, _ := opts.String("<env>")

    version := getVersion(true, true)

    envVars := map[string]string{
        "WARP_VAULT_HOME": *state.warpSettings.VaultHome,
        "WARP_KEYS_HOME": *state.warpSettings.KeysHome,
        "WARP_REPO": *state.warpSettings.DockerRepoName,
        "WARP_VERSION": version,
        "WARP_ENV": env,
    }

    makeCommand := exec.Command("make")
    makeCommand.Dir = makfileDir
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


func deploy(opts docopt.Opts, args CtlArgs) {
  // repos are <env>-<service>
  // deploy is just tagging an image in dockerhub with the <block>-latest tag

  // deploy worker
  // go deploy worker run
  // poll deploy worker status that samples the lb routes n times and tracks the percent of versions
  // when all versions are stabilized, stop


    env, _ := opts.String("<env>")
    service, _ := opts.String("<service>")

    // (<version> | latest-local | latest-beta | latest)

    var deployVersion string

    if version, err := opts.String("<service>"); err == nil {
        deployVersion = version
    } else {
        versions := listVersions(env, service)

        var filteredVersions []*semver.Version = []*semver.Version{}

        if latestLocal, _ = opts.Bool("latest-local"); latestLocal {
            // keep only versions with pre release of this hostname
            hostname := os.Hostname()
            for _, version := range versions {
                if version.PreRelease == hostname {
                    filteredVersions = append(filteredVersions. version)
                }
            }
        } else if latestBeta, _ = opts.Bool("latest-beta"); latestBeta {
            // keep only versions with pre release of beta
            for _, version := range versions {
                if version.PreRelease == "beta" {
                    filteredVersions = append(filteredVersions. version)
                }
            }
        } else if latest, _ = opts.Bool("latest"); latest {
            // keep only versions with no pre release
            for _, version := range versions {
                if version.PreRelease == "" {
                    filteredVersions = append(filteredVersions. version)
                }
            }
        } else {
            panic("Unknown filter.")
        }

        if len(filteredVersions) == 0 {
            panic("No matching versions.")
        }

        // sort the filtered versions and take the max
        semver.Sort(filteredVersions)
        deployVersion = filteredVersions[len(filteredVersions) - 1].String()
    }

    fmt.Printf("Selected version %s\n", deployVersion)

    // remove all "<block>-latest" tags
    // add <block>-latest tags to the image matching the deploy version

    blocks := listBlocks(env, service)

    var deployBlocks []string = []string{}

    if blocklist, err = opts.String("<blocklist>"); err == nil {
        blockmap := map[string]bool{}
        for _, block := range strings.Split(blocklist, ",") {
            blockmap[block] = true
        }
        for _, block := range blocks {
            if _, ok = blockmap[block]; ok {
                deployBlocks = append(deployBlocks, block)
            }
        }
    } else if percent, err = opts.Int("--percent"); err == nil {
        blockCount = math.Ceil(len(blocks) * percent / 100.0)
        deployBlocks = append(deployBlocks, blocks[:blockCount]..)
    } else {
        panic("No matching blocks.")
    }

    if len(deployBlocks) == 0 {
        panic("No matching blocks.")
    }

    announceDeployStarted(env, service, deployBlocks, deployVersion)

    for _, block := range deployBlocks {
        // FIXME
        // remove tag <block>-latest from current
        // tag imageId with <block>-latest

        sourceImageName := fmt.Sprintf("%s/%s-%s:%s", dockerRepoName, env, service, convertVersionToDocker(deployVersion))
        deployImageName := fmt.Sprintf("%s/%s-%s:%s-latest", dockerRepoName, env, service, block)

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

    // FIXME
    // query the internal load balancer for the service/block/version until the version stabilizes
    // SAMPLE THIS: canary-lb.bringyour.com/by/b/{service}/{block}/status

    blockStatusUntil(env, service, deployBlocks, deployVersion)

    announceDeployEnded(env, service, deployBlocks, deployVersion)
}


func deployLocal(opts docopt.Opts, args CtlArgs) {
  opts["latest-local"] = true
  deploy(opts, args)
}

func deployBeta(opts docopt.Opts, args CtlArgs) {
  opts["latest-beta"] = true
  deploy(opts, args)
}

func deployRelease(opts docopt.Opts, args CtlArgs) {
  opts["latest"] = true
  deploy(opts, args)
}

func lsVersion(opts docopt.Opts, args CtlArgs) {
  build, _ := opts.Bool("-b")
  docker, _ := opts.Bool("-d")
  version := getVersion(build, docker)
  fmt.Printf("%s\n", version)
}

func lsServices(opts docopt.Opts, args CtlArgs) {
}

func lsServiceBlocks(opts docopt.Opts, args CtlArgs) {
}

func lsVersions(opts docopt.Opts, args CtlArgs) {
}

func lbCreateConfig(opts docopt.Opts, args CtlArgs) {
  fmt.Printf("nginx config\n")
}

func serviceRun(opts docopt.Opts, args CtlArgs) {
  // must have root permissions
  // for lb, set up route table; set up lb network; add lb network to service network
  // 
}
    
func serviceCreateUnit(opts docopt.Opts, args CtlArgs) {
  // for lb, get the routing table from the config file
}
  
func createUnits(opts docopt.Opts, args CtlArgs) {
}


