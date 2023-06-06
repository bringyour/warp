package main

import (
    "fmt"
    "os"
    "path"
    "encoding/json"

    "github.com/docopt/docopt-go"
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
2. Build services. This includes signing and publishing docker images to repo.
3. Deploy services. This includes tagging docker images in a repo as "latest".
4. Run services. This includes watching for image attributes and starting new containers while draining old ones.
   Zero downtime means routing new connections to the new containers while the old ones drain.

Steps 1-3 happen on a developer or build machine. Step 4 happens on production machines in the target environment.

Usage:
  warpctl init
    [--docker_repo_name=<docker_repo_name>]
    [--dockerhub_token=<dockerhub_token>]
    [--vault_home=<vault_home>]
    [--keys_home=<keys_home>]
  warpctl version stage (local | sync | next (beta | release))
  warpctl build <env> <Makefile>
  warpctl deploy <env> <service>
    (<version> | latest-local | latest-beta | latest)
    (<blocks> | --percent=<percent>)
  warpctl deploy-local <env> <service> [--percent=<percent>]
  warpctl deploy-beta <env> <service> [--percent=<percent>]
  warpctl deploy-release <env> <service> [--percent=<percent>]
  warpctl ls version [-b]
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
  --percent=<percent>        Deploy to a percent of blocks, ordered lexicographically with beta first.
                             The block count is rounded up to the nearest int. 
  -b                         Include the build timestamp in the version. Use this for builds.
  --target_warp_home=<target_warp_home>  WARP_HOME for the unit.
  --outdir=<outdir>          Output dir.
  `

  opts, err := docopt.ParseArgs(usage, os.Args[1:], WARP_VERSION)
  if err != nil {
    panic(err)
  }

  args := CtlArgs{}
  opts.Bind(&args)

  if init_, _ := opts.Bool("init"); init_ {
    initWarp(opts, args)
  } else if version, _ := opts.Bool("version"); version {
    if stage, _ := opts.Bool("stage"); stage {
      versionStage(opts, args)
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
  // home dir
  // settings

  warpHome string
  warpVersionHome string
  // warp.json
  warpSettings *WarpSettings
  // version.json
  versionSettings *VersionSettings
}


type WarpSettings struct {
  DockerHubToken *string `json:"dockerHubToken,omitempty"`
  VaultHome *string `json:"vaultHome,omitempty"`
  KeysHome *string `json:"keysHome,omitempty"`
}


type VersionSettings struct {
  StagedVersion *string `json:"stagedVersion,omitempty"`
}



func GetWarpState() *WarpState {
  // env WARP_HOME
  // env WARP_VERSION_HOME

  warpHome := os.Getenv("WARP_HOME")
  warpVersionHome := os.Getenv("WARP_VERSION_HOME")

  // FIXME if file does not exist or parse fails, use empty object
  warpJson := os.ReadFile(path.Join(warpHome, "warp.json"))
  var warpSettings WarpSettings
  json.Unmarshal(warpJson, &warpSettings)

  // FIXME if file does not exist or parse fails, use empty object
  versionJson := os.ReadFile(path.Join(warpVersionHome, "version.json"))
  var versionSettings VersionSettings
  json.Unmarshal(warpJson, &versionSettings)

  return &WarpState{
    warpHome: warpHome,
    warpVersionHome: warpVersionHome,
    warpSettings: &warpSettings,
    versionSettings: &versionSettings,
  }
}


func SetWarpState(state *WarpState) {
  // FIXME write the files
}



// https://github.com/coreos/go-semver


func initWarp(opts docopt.Opts, args CtlArgs) {
}

func versionStage(opts docopt.Opts, args CtlArgs) {
  state := GetWarpState()


  // if local version, do not pull git or push



  // git reset --hard
  // git pull warp version home

  // goVersion := fmt.Sprintf("v%s", state.versionSettings.stagedVersion)
  // [-next | <version>] [-beta | -release]

  if next {
    // version is date based except for the patch
    version := fmt.Sprintf("%s.%s.%s", YY, MM, semver.Patch(goVersion) + 1)
  } else {
    version := optionVersion
  }

  if beta {
    // add -beta prerelease
  } else if release {
    // strip the prerelease
  }

  // git commit 

}


func build(opts docopt.Opts, args CtlArgs) {

}


// warpctl deploy <env> <service>
//     (<version> | latest-beta | latest)
//     (<blocks> | --percent=<percent>)



func deploy(opts docopt.Opts, args CtlArgs) {
  // repos are <env>-<service>
  // deploy is just tagging an image in dockerhub with the <block>-latest tag

  // deploy worker
  // go deploy worker run
  // poll deploy worker status that samples the lb routes n times and tracks the percent of versions
  // when all versions are stabilized, stop
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
  // FIXME
  // if -b show a +<timestamp> on the staged version
  // builds should use this always to tag the build

  state := GetWarpState()

  // no need to git sync, just use the file in place

  // go semver requires a leading "v"
  // goVersion = fmt.Sprintf("v%s", state.versionSettings.stagedVersion)
  if build {
    buildTimestamp := time.Now()
    return fmt.Sprintf("%s+%u", state.versionSettings.stagedVersion, buildTimestamp)
  } else {
    return state.versionSettings.stagedVersion
  }
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


