
all: clean build image

clean:
	rm -rf build

build:
	# generate the config
	mkdir -p build/${WARP_ENV}/nginx.conf
	for block in `warpctl lb list-blocks ${WARP_ENV}`; do \
		warpctl lb create-config ${WARP_ENV} $${block} --out="build/${WARP_ENV}/nginx.conf/$${block}.conf"; \
	done
	echo "{\"version\":\"${WARP_VERSION}\",\"status\":\"ok\"}" > build/${WARP_ENV}/status

image:
	# --no-cache to always regenerate the encryption data
	# --progress=plain to Dockerfile command output
	docker buildx build --progress=plain --build-arg warp_env=${WARP_ENV} --platform linux/arm64/v8,linux/amd64 . -t ${WARP_DOCKER_NAMESPACE}/${WARP_ENV}-lb:${WARP_VERSION} --no-cache --push
