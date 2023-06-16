# warp
Warp control. Fluid iteration and zero downtime continuous release.

[[DEMO SCREEN]]


## Overview

The goal of warp is to maximize developer productivity and minimize service downtime. It does this by having a convention for iterating and deploying services.

0. Develop and test locally
1. Stage a version
2. Build services
   This includes signing and pushing docker images.
3. Deploy services to an environment
   This includes tagging docker images in a repo as "latest" and targeting one or more deployment "blocks"
4. Run services in an environment
   This includes watching for image attributes and starting new containers while draining old ones.


Warp creates a lb per interface on each host, which redirects to services running locally on that host. The DNS for each service should be configured to point to multiple lbs for redundancy and load balancing.

To scale up, add more hosts/lbs. These can be in the cloud or in colos. Each host can run a partial set of services.



## Get started

Build the `warpctl` tool, add it to the PATH.

```
cd warpctl
make
export PATH="$PATH:$(pwd)/build"
warpctl
```


Define WARP_HOME to be your project home.

Create these directories in your project

```
$WARP_HOME
	config/
	  local/ # this is the env name
	    # add files that your services read to configure their behavior
	vault/
	  local/
	    services.yml
	    # add files for service credentials and secret keys
	    tls/
	      star_mydomain_com/
	        star_mydomain_com.pem
	        star_mydomain_com.key
	site/
	  # add files specific to this host
```

Edit `vault/local/services.yml` to define your services.

```
EXAMPLE
```






## Run locally

The `local_lb` target of the makefile runs the lb locally and edit `/etc/hostnames` to correctly direct the service hostnames.

```
make local_lb
```

Use `warpctl runlocal` to run each service locally.

```
warpctl runlocal api/Makefile
```


# Set up an environment

Create systemctl units for all your services.

```
warpctl service create-units <env> <outdir>
```

The units are organized by host. Install,

On the target host, create the target warp home

```
/srv/warp
  config
  vault
  site
```

Set up the vault manually or using a tool like Ansible. Config is deployed using the `config-updater` service. Local is for settings specific to this host, whcih can be done manually or with a tool like Ansible. For example this can be settings with routes to services that are site specific.


## Build and deploy

```
warpctl stage version next beta
warpctl build <Makefile>
warpctl deployXXX

warpctl stage version next
warpctl build <Makefile>
warpctl deployXXX
```






## Services

Every service needs a makefile that builds and publishes a docker image. The makefile should use these env vars:

ENV VARS

Every service you create that listens on port 80 must repond to the `/status` path with an object:

```
{
	version
	configVersion
	status
}
```







## MacOS local setup

sudo scutil --set HostName outerwerld
sudo scutil --set LocalHostName outerwerld
sudo scutil --set ComputerName outerwerld








The warp lifecycle is:
0. Develop and test locally
1. Stage a version
2. Build services
   This includes signing and pushing docker images.
3. Deploy services to an environment
   This includes tagging docker images in a repo as "latest" and targeting one or more deployment "blocks"
4. Run services
   This includes watching for image attributes and starting new containers while draining old ones.

Steps 0-3 happen on a developer or build machine. Step 4 happens on production machines in the target environment.


