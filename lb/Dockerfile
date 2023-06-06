FROM ubuntu:22.04
# see https://docs.docker.com/develop/develop-images/dockerfile_best-practices/

RUN apt-get update && apt-get install -y \
	nginx \
	openssl \
 && rm -rf /var/lib/apt/lists/*
RUN openssl dhparam -dsaparam -out /etc/nginx/dhparam.pem 4096

COPY build/${WARP_ENV}/nginx.conf /etc/nginx/nginx.conf
EXPOSE 80
EXPOSE 443
# see https://ubuntu.com/blog/avoiding-dropped-connections-in-nginx-containers-with-stopsignal-sigquit
STOPSIGNAL SIGQUIT
CMD ["nginx", "-g", "daemon off;"]
