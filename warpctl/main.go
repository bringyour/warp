package main

import (
    // "fmt"
    "os"
    // "encoding/json"

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

// warpctl lb run <env> <interface_name>
//  warpctl lb create-unit <env> <interface_name> [--target_warp_home=<target_warp_home>]
//  warpctl key-updater run <env>
//  warpctl key-updater create-unit <env>


// needs a docker hub user access token
func main() {
    usage := `Warp control. Zero downtime continuous release.

Usage:
  warpctl init
    [--dockerhub_token=<dockerhub_token>]
    [--vault_home=<vault_home>]
    [--keys_home=<keys_home>]
  warpctl version stage [-next | <version>] [-beta | -release]
  warpctl deploy <env> <service>
    (<version> | latest-beta | latest)
    (<blocks> | --percent=<percent>)
  warpctl deploy-beta <env> <service> [--percent=<percent>]
  warpctl deploy-release <env> <service> [--percent=<percent>]
  warpctl ls version [-b]
  warpctl ls services
  warpctl ls service-blocks [<service>]
  warpctl ls versions [<service>]
  warpctl lb create-config <env>
  warpctl service run <env> <service> <block>
  warpctl service create-unit <env> <service> <block>
    [--target_warp_home=<target_warp_home>]
  warpctl create-units <env> --outdir=<outdir>
    [--target_warp_home=<target_warp_home>]

Options:
  -h --help                  Show this screen.
  --version                  Show version.
  --dockerhub_token=<dockerhub_token>  Your dockerhub token.
  --vault_home=<vault_home>  Secure vault home (keys-red).
  --keys_home=<keys_home>    Keys home.
  -next                      Generate the next version, using a time increment semver yyyy.mm.bb .
  -beta                      Switch to beta version, yyyy.mm.bb-beta .
  -release                   Switch to release version, yyyy.mm.bb .
  --percent=<percent>        Deploy to a percent of blocks, ordered lexicographically with beta first.
                             The block count is rounded up to the nearest int. 
  -b                         Include the build timestamp in the version.
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
  } else if deploy_, _ := opts.Bool("deploy"); deploy_ {
    deploy(opts, args)
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
      lbCreateVersion(opts, args)
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


func initWarp(opts docopt.Opts, args CtlArgs) {
}

func versionStage(opts docopt.Opts, args CtlArgs) {
}

func deploy(opts docopt.Opts, args CtlArgs) {
}

func deployBeta(opts docopt.Opts, args CtlArgs) {
}

func deployRelease(opts docopt.Opts, args CtlArgs) {
}

func lsVersion(opts docopt.Opts, args CtlArgs) {
}

func lsServices(opts docopt.Opts, args CtlArgs) {
}

func lsServiceBlocks(opts docopt.Opts, args CtlArgs) {
}

func lsVersions(opts docopt.Opts, args CtlArgs) {
}
    
func lbCreateVersion(opts docopt.Opts, args CtlArgs) {
}

func serviceRun(opts docopt.Opts, args CtlArgs) {
}
    
func serviceCreateUnit(opts docopt.Opts, args CtlArgs) {
}
  
func createUnits(opts docopt.Opts, args CtlArgs) {
}


