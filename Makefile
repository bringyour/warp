
all: local_lb

# note for mobile dev, you will need to also add DNS entries for the env aliases
# (e.g. <host>-<service>.<domain>)
# to be the IP of this host on the LAN shared with the mobile devices
local_routing_on:
	sudo hostctl add domains warp_local $(warpctl lb list-hostnames local --envalias=${HOST})

local_routing_off:
	sudo hostctl remove warp_local

# using env local, runs an lb for local development
# build and locally run each service with `warpctl runlocal <path/to/service>/Makefile`
local_lb:
	# make sure we are on a local version. `runlocal` will fail otherwise
	warpctl stage version local
	$(MAKE) local_routing_on
	trap "$(MAKE) local_routing_off" EXIT && $(MAKE) run_local_lb

run_local_lb:
	warpctl run-local lb/Makefile --envalias=${HOST}
