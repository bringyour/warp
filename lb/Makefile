
all: clean build image

clean:
	rm -rf build

build:
	# generate the config
	mkdir -p build/${WARP_ENV}
	warpctl lb create-config ${WARP_ENV} > build/${WARP_ENV}/nginx.conf

image:
	# --no-cache to always regenerate the encryption data
	docker buildx build --platform linux/arm64/v8,linux/amd64 . -t ${WARP_NAMESPACE}/${WARP_ENV}-lb:${WARP_VERSION} --no-cache --push
