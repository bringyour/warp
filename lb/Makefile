
all: clean build image

clean:
	rm -rf build

build:
	# generate the config
	mkdir -p build/${WARP_ENV}/nginx.conf
	warpctl lb create-config ${WARP_ENV} --out=build/${WARP_ENV}/nginx.conf;
	echo "{\"version\":\"${WARP_VERSION}\",\"status\":\"ok\"}" > build/${WARP_ENV}/status.json
	# build the units for reference
	mkdir -p build/${WARP_ENV}/systemd
	warpctl service create-units ${WARP_ENV} --out=build/${WARP_ENV}/systemd;

image:
	# --no-cache to always regenerate the encryption data
	# --progress=plain to Dockerfile command output
	docker buildx build --progress=plain \
		--build-arg warp_env=${WARP_ENV} \
		--platform linux/arm64/v8,linux/amd64 \
		-t ${WARP_DOCKER_NAMESPACE}/${WARP_ENV}-lb:${WARP_VERSION} \
		--no-cache \
		--push \
		.
