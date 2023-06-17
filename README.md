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
	  myfirstenv/
	vault/
	  local/
	    services.yml
	  myfirstenv/
	   	services.yml
      tls/
        star_mydomain_com/
          star_mydomain_com.pem
          star_mydomain_com.key
	site/
	  # add files specific to this host
```

Edit `vault/local/services.yml` inside an env to define the services and hosts for that env.

```
EXAMPLE
```


# What is config?

Config are like hard coded configuration that your services read. This can be anything that tunes the behavior of the services, including ml weights.

Instead of creating new service versions to deploy new configurations, new config is injected into existing versions using the config-updater. This is like changing the command line args but for all the config files.



# What is vault?

This is where you put sensistive files that should never be in a docker repo. These are usually stored in some encrypoted way and set up on the target host in some secure way.





## Run locally

The `local_lb` target of the warp makefile runs the lb locally and edit `/etc/hostnames` to correctly direct the service hostnames. The hostname your dev computer is also used as an alias so that you can create DNS entries for your dev computer for second-device/mobile testing. 

```
make local_lb
```

Use `warpctl runlocal` to run each service locally.

```
warpctl runlocal /path/to/your/service/Makefile
```


# Set up a deployment environment

You create a deployment environment where you want services to run. Each environment needs a host and a network interface. Each network interface runs its own lb. For example if you have three interfaces, you can have three public IPs and run three lbs. The lb is meant to receive traffic directly from the internet without a NAT so that the source IPs are preserved.

Create systemd units for all your services.

```
warpctl service create-units <env> <outdir> --targetwarphome=/srv/warp
```

The units are organized by host.


On the target server host, create the target warp home.

```
/srv/warp
  config
  vault
  site
```

Configure vault and site outside of warp (e.g. ansible or some secure system image tool). We will deploy the config as the final step.

Copy warpctl the host at /usr/local/bin.

```
export WARP_HOME=/srv/warp
warpctl init XXX
```

Now copy the systemd units into place (/etc/system/system.d/) and enable all the units.

As your first deployment, deploy the config-updater from your dev computer.

```
warpctl stage version next
warpctl build config-updater/<Makefile>
warpctl deploy XXX
```



## Build and deploy

```
warpctl stage version next beta
warpctl build <Makefile>
warpctl deployXXX

warpctl stage version next
warpctl build <Makefile>
warpctl deployXXX
```






## Service requirements

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


