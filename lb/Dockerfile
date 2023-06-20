FROM ubuntu:22.04
# see https://docs.docker.com/develop/develop-images/dockerfile_best-practices/

ARG warp_env
ENV WARP_ENV=$warp_env

RUN apt-get update && apt-get install -y \
	nginx \
	openssl \
 && rm -rf /var/lib/apt/lists/*
RUN openssl dhparam -dsaparam -out /etc/nginx/dhparam.pem 4096

COPY build/${WARP_ENV}/status /srv/warp/status/status

ADD build/${WARP_ENV}/nginx.conf /srv/warp/nginx.conf
EXPOSE 80
EXPOSE 443
# see https://ubuntu.com/blog/avoiding-dropped-connections-in-nginx-containers-with-stopsignal-sigquit
STOPSIGNAL SIGQUIT
# this expects container args to be the path to the config, e.g. "/srv/warp/nginx.conf/${WARP_BLOCK}.conf"
ENTRYPOINT ["nginx", "-g", "daemon off;", "-c"]
